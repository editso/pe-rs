use crate::*;

pub struct X64PE(*mut u8);

impl PeParse for X64PE {

    fn parse_exports(ptr: *mut u8, sections: &[Section], virtual_address: usize) -> Result<Vec<Export>>
    where
            Self: Sized, {
        unimplemented!()
    }

    
    fn parse(ptr: *mut u8) -> Result<PE> {
        unsafe {
            let dos = try_as!(IMAGE_DOS_HEADER, ptr);

            if dos.e_magic != IMAGE_DOS_SIGNATURE {
                return Err(Error::InvalidPE);
            }

            let offset_of_nt_header = dos.e_lfanew as usize;

            let nt = try_as!(IMAGE_NT_HEADERS64, ptr, offset_of_nt_header);

            if nt.Signature != IMAGE_NT_SIGNATURE {
                return Err(Error::InvalidPE);
            }

            if nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
                return Err(Error::InvalidPE);
            }

            let opt = &nt.OptionalHeader;

            let size_of_optional_header = nt.FileHeader.SizeOfOptionalHeader as usize;

            let offset_of_file_header = offset_of_nt_header + sizeof!(DWORD);

            let offset_of_optional_header = offset_of_file_header + IMAGE_FILE_HEADER::size();

            let offset_of_section_header = offset_of_optional_header + size_of_optional_header;

            let number_of_section = nt.FileHeader.NumberOfSections as usize;

            // 节表信息
            let sections = Self::parse_section(ptr, number_of_section, offset_of_section_header)?;

            // 导出表 rva
            let export_rva =
                opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress as usize;

            if export_rva != 0 {
                let fov = export_rva.to_fov(&sections)?;
            }

            // 导入表 rva
            let import_rva =
                opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress as usize;

            Self::parse_import(ptr, &sections, import_rva)?;

            // 重定位表 rva
            let reloc_rva =
                opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress as usize;

            Self::parse_import(ptr, &sections, reloc_rva)?;
        }

        println!("x64");
        unimplemented!()
    }
}
