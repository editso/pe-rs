use std::fmt::Debug;

use c2rs::c2rs_def;

pub type WORD = std::os::raw::c_ushort;
pub type DWORD = std::os::raw::c_uint;
pub type BYTE = std::os::raw::c_uchar;
pub type LONG = std::os::raw::c_ulong;
pub type ULONGLONG = std::os::raw::c_ulonglong;
pub type CHAR = u8;

pub const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;
pub const IMAGE_SIZEOF_SHORT_NAME: usize = 8;

// nt signature
pub const IMAGE_NT_SIGNATURE: DWORD = 0x0000_4550;
// dos signature
pub const IMAGE_DOS_SIGNATURE: WORD = 0x5A4D;

// X86
pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC: WORD = 0x10b;
// X64
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: WORD = 0x20b;
// ROM
pub const IMAGE_ROM_OPTIONAL_HDR_MAGIC: WORD = 0x107;

/// Data Directory
/// Architecture-specific data
pub const IMAGE_DIRECTORY_ENTRY_ARCHITECTURE: usize = 7;
/// Base relocation table
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
/// Bound import directory
pub const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: usize = 11;
/// COM descriptor table
pub const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;
/// Debug directory
pub const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
/// Delay import table
pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
/// Exception directory
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
/// Export directory
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
/// The relative virtual address of global pointer
pub const IMAGE_DIRECTORY_ENTRY_GLOBALPTR: usize = 8;
/// Import address table
pub const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;
/// Import directory
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
/// Load configuration directory
pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10;
/// Resource directory
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
/// Security directory
pub const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
/// Thread local storage directory
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;

c2rs_def!(
    struct IMAGE_DOS_HEADER {              // DOS .EXE header
        WORD   e_magic;                     // * Magic number
        WORD   e_cblp;                      // Bytes on last page of file
        WORD   e_cp;                        // Pages in file
        WORD   e_crlc;                      // Relocations
        WORD   e_cparhdr;                   // Size of header in paragraphs
        WORD   e_minalloc;                  // Minimum extra paragraphs needed
        WORD   e_maxalloc;                  // Maximum extra paragraphs needed
        WORD   e_ss;                        // Initial (relative) SS value
        WORD   e_sp;                        // Initial SP value
        WORD   e_csum;                      // Checksum
        WORD   e_ip;                        // Initial IP value
        WORD   e_cs;                        // Initial (relative) CS value
        WORD   e_lfarlc;                    // File address of relocation table
        WORD   e_ovno;                      // Overlay number
        WORD   e_res[4];                    // Reserved words
        WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
        WORD   e_oeminfo;                   // OEM information; e_oemid specific
        WORD   e_res2[10];                  // Reserved words
        LONG   e_lfanew;                    // * File address of new exe header
    };

    struct IMAGE_FILE_HEADER {
        WORD  Machine;              //  IMAGE_FILE_MACHINE_I386(0x014c) , IMAGE_FILE_MACHINE_IA64(0x0200), IMAGE_FILE_MACHINE_AMD64(0x8664)
        WORD  NumberOfSections;     // *
        DWORD TimeDateStamp;        // -
        DWORD PointerToSymbolTable; // -
        DWORD NumberOfSymbols;      // -
        WORD  SizeOfOptionalHeader; // *
        WORD  Characteristics;      // *
    };

    struct IMAGE_OPTIONAL_HEADER32 {
        WORD                 Magic;
        BYTE                 MajorLinkerVersion;
        BYTE                 MinorLinkerVersion;
        DWORD                SizeOfCode;
        DWORD                SizeOfInitializedData;
        DWORD                SizeOfUninitializedData;
        DWORD                AddressOfEntryPoint;
        DWORD                BaseOfCode;
        DWORD                BaseOfData;
        DWORD                ImageBase;
        DWORD                SectionAlignment;
        DWORD                FileAlignment;
        WORD                 MajorOperatingSystemVersion;
        WORD                 MinorOperatingSystemVersion;
        WORD                 MajorImageVersion;
        WORD                 MinorImageVersion;
        WORD                 MajorSubsystemVersion;
        WORD                 MinorSubsystemVersion;
        DWORD                Win32VersionValue;
        DWORD                SizeOfImage;
        DWORD                SizeOfHeaders;
        DWORD                CheckSum;
        WORD                 Subsystem;
        WORD                 DllCharacteristics;
        DWORD                SizeOfStackReserve;
        DWORD                SizeOfStackCommit;
        DWORD                SizeOfHeapReserve;
        DWORD                SizeOfHeapCommit;
        DWORD                LoaderFlags;
        DWORD                NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    };

    struct IMAGE_OPTIONAL_HEADER64 {
        WORD                 Magic;                       // *
        BYTE                 MajorLinkerVersion;          // -
        BYTE                 MinorLinkerVersion;          // -
        DWORD                SizeOfCode;                  // -
        DWORD                SizeOfInitializedData;       // -
        DWORD                SizeOfUninitializedData;     // -
        DWORD                AddressOfEntryPoint;         // *
        DWORD                BaseOfCode;                  // -
        ULONGLONG            ImageBase;                   // *
        DWORD                SectionAlignment;            // *
        DWORD                FileAlignment;               // *
        WORD                 MajorOperatingSystemVersion; // -
        WORD                 MinorOperatingSystemVersion; // -
        WORD                 MajorImageVersion;           // -
        WORD                 MinorImageVersion;           // -
        WORD                 MajorSubsystemVersion;       // -
        WORD                 MinorSubsystemVersion;       // -
        DWORD                Win32VersionValue;           // -
        DWORD                SizeOfImage;                 // *
        DWORD                SizeOfHeaders;               // *
        DWORD                CheckSum;                    // -
        WORD                 Subsystem;                   // -
        WORD                 DllCharacteristics;          // -
        ULONGLONG            SizeOfStackReserve;          // -
        ULONGLONG            SizeOfStackCommit;           // -
        ULONGLONG            SizeOfHeapReserve;           // -
        ULONGLONG            SizeOfHeapCommit;            // -
        DWORD                LoaderFlags;                 // -
        DWORD                NumberOfRvaAndSizes;         // -
        IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    };

    struct IMAGE_SECTION_HEADER {
        BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
        union {
          DWORD PhysicalAddress;
          DWORD VirtualSize;
        } Misc;
        DWORD VirtualAddress;
        DWORD SizeOfRawData;
        DWORD PointerToRawData;
        DWORD PointerToRelocations;
        DWORD PointerToLinenumbers;
        WORD  NumberOfRelocations;
        WORD  NumberOfLinenumbers;
        DWORD Characteristics;
    };

    struct IMAGE_NT_HEADERS {
        DWORD Signature;
        IMAGE_FILE_HEADER FileHeader;
        IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    };

    struct IMAGE_NT_HEADERS64 {
        DWORD                   Signature;
        IMAGE_FILE_HEADER       FileHeader;
        IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    };

    struct IMAGE_DATA_DIRECTORY {
        DWORD VirtualAddress;
        DWORD Size;
    };

    // 导入表
    struct IMAGE_IMPORT_DESCRIPTOR {
        union {
            DWORD   Characteristics;            // 0 for terminating null import descriptor
            DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
        } DUMMYUNIONNAME;
        DWORD   TimeDateStamp;                  // 0 if not bound,
                                                // -1 if bound, and real date\time stamp
                                                //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                                // O.W. date/time stamp of DLL bound to (Old BIND)

        DWORD   ForwarderChain;                 // -1 if no forwarders
        DWORD   Name;
        DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
    };

    // 以名称导入
    struct IMAGE_IMPORT_BY_NAME {
        WORD    Hint;
        CHAR   Name[1];
    };

    // iat
    struct IMAGE_THUNK_DATA32 {
        union {
            DWORD ForwarderString;      // PBYTE
            DWORD Function;             // PDWORD
            DWORD Ordinal;
            DWORD AddressOfData;        // PIMAGE_IMPORT_BY_NAME
        } u1;
    };

    struct IMAGE_THUNK_DATA64{
        union{
            ULONGLONG ForwarderString;      // PBYTE
            ULONGLONG Function;             // PDWORD
            ULONGLONG Ordinal;
            ULONGLONG AddressOfData;        // PIMAGE_IMPORT_BY_NAME
        }u1;
    };

    // 重定位表
    struct IMAGE_BASE_RELOCATION {
        DWORD   VirtualAddress;
        DWORD   SizeOfBlock;
    //  WORD    TypeOffset[1];
    };
);
