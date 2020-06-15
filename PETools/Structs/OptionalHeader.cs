using System;
using System.Runtime.InteropServices;

namespace PETools
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_OPTIONAL_HEADER_STANDARD
    {
        public const ushort MAGIC_PE32 = 0x10B;
        public const ushort MAGIC_ROM = 0x107;
        public const ushort MAGIC_PE32PLUS = 0x20B;

        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_OPTIONAL_HEADER_32
    {
        public uint BaseOfData; //PE32 only
        //Windows Specific fields
        public uint ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public IMAGE_SUBSYSTEM Subsystem;
        public IMAGE_DLLCCHARACTERISTICS DllCharacteristics;
        public uint SizeOfStackReserve;
        public uint SizeOfStackCommit;
        public uint SizeOfHeapReserve;
        public uint SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_OPTIONAL_HEADER_32PLUS
    {
        //PE32+ does not have BaseOfData
        //Windows Specific fields
        public ulong ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public IMAGE_SUBSYSTEM Subsystem;
        public IMAGE_DLLCCHARACTERISTICS DllCharacteristics;
        public ulong SizeOfStackReserve;
        public ulong SizeOfStackCommit;
        public ulong SizeOfHeapReserve;
        public ulong SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
    }

#pragma warning disable CA1712 // Do not prefix enum values with type name
    public enum IMAGE_SUBSYSTEM : ushort
    {
        IMAGE_SUBSYSTEM_UNKNOWN = 0, //An unknown subsystem
        IMAGE_SUBSYSTEM_NATIVE = 1, //Device drivers and native Windows processes
        IMAGE_SUBSYSTEM_WINDOWS_GUI = 2, //The Windows graphical user interface (GUI) subsystem
        IMAGE_SUBSYSTEM_WINDOWS_CUI = 3, //The Windows character subsystem
        IMAGE_SUBSYSTEM_OS2_CUI = 5, //The OS/2 character subsystem
        IMAGE_SUBSYSTEM_POSIX_CUI = 7, //The Posix character subsystem
        IMAGE_SUBSYSTEM_NATIVE_WINDOWS = 8, //Native Win9x driver
        IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9, //Windows CE
        IMAGE_SUBSYSTEM_EFI_APPLICATION = 10, //An Extensible Firmware Interface (EFI) application
        IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11, //An EFI driver with boot services
        IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12, //An EFI driver with run-time services
        IMAGE_SUBSYSTEM_EFI_ROM = 13, //An EFI ROM image
        IMAGE_SUBSYSTEM_XBOX = 14, //XBOX
        IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16, //Windows boot application. 
    }
#pragma warning restore CA1712

    [Flags]
    public enum IMAGE_DLLCCHARACTERISTICS : ushort
    {
        IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020, //Image can handle a high entropy 64-bit virtual address space.
        IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040, //DLL can be relocated at load time.
        IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080, //Code Integrity checks are enforced.
        IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100, //Image is NX compatible.
        IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200, //Isolation aware, but do not isolate the image.
        IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400, //Does not use structured exception (SE) handling. No SE handler may be called in this image.
        IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800, //Do not bind the image.
        IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000, //Image must execute in an AppContainer.
        IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000, //A WDM driver.
        IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000, //Image supports Control Flow Guard.
        IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000, //Terminal Server aware. 
    }
}
