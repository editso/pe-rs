use std::collections::HashMap;

use crate::*;

pub struct X86PE(*mut u8);

impl PeParse for X86PE {
    fn parse_import(
        ptr: *mut u8,
        sections: &[Section],
        virtual_address: usize,
    ) -> Result<HashMap<String, Vec<Import>>>
    where
        Self: Sized,
    {
        let mut import_map = HashMap::new();

        unsafe {
            let imports = try_ptr!(
                IMAGE_IMPORT_DESCRIPTOR,
                ptr,
                virtual_address.to_fov(sections)?
            );

            try_ptr_loop!((import, _offset) in imports => {
                if import.FirstThunk == 0 {
                    break;
                }

                let mut import_functions = Vec::new();

                let mut name = Vec::new();

                os_str!(name in ptr.offset(import.Name.to_fov(sections)? as isize));

                let name = String::from_utf8(name).unwrap();

                let iats = try_ptr!(
                    IMAGE_THUNK_DATA32,
                    ptr,
                    import.FirstThunk.to_fov(sections)?
                );

                try_ptr_loop!((iat, offset) in iats => {

                    if iat.u1.AddressOfData == 0{
                        break;
                    }

                    let offset = offset - ptr as usize;

                    // 最高位如果为1说明是以序号导入
                    // 否则则按名称导入
                    let import = if iat.u1.Ordinal >> 31 == 1{
                        Import::Ordinal(
                            Ordinal{
                                offset_of_iat: offset,
                                ordinal: (iat.u1.Ordinal & !(0b1 << 31)) as usize
                            }
                        )
                    }else{
                        let iin = try_as!(IMAGE_IMPORT_BY_NAME, ptr, iat.u1.Function.to_fov(sections)?);

                        let mut name = Vec::new();

                        os_str!(name in iin.Name.as_mut_ptr());

                        Import::Function(Function{
                            offset_of_iat: offset,
                            name: String::from_utf8(name).unwrap(),
                        })

                    };

                    import_functions.push(import);

                });

                import_map.insert(name, import_functions);
            });
        }

        Ok(import_map)
    }

    fn parse(ptr: *mut u8) -> Result<PE> {
        unsafe {
            let dos = try_as!(IMAGE_DOS_HEADER, ptr);

            if dos.e_magic != IMAGE_DOS_SIGNATURE {
                return Err(Error::InvalidPE);
            }

            let offset_of_nt_header = dos.e_lfanew as usize;

            let nt = try_as!(IMAGE_NT_HEADERS, ptr, offset_of_nt_header);

            if nt.Signature != IMAGE_NT_SIGNATURE {
                return Err(Error::InvalidPE);
            }

            if nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC {
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

            let exports = if export_rva != 0 {
                Self::parse_exports(ptr, &sections, export_rva)?
            } else {
                Vec::new()
            };

            // 导入表 rva
            let import_rva =
                opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress as usize;

            let imports = if import_rva != 0 {
                Self::parse_import(ptr, &sections, import_rva)?
            } else {
                HashMap::new()
            };

            // 重定位表 rva
            let reloc_rva =
                opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress as usize;

            let relocs = if reloc_rva != 0 {
                Self::parse_reloc(ptr, &sections, reloc_rva)?
            } else {
                Vec::new()
            };

            Ok(PE {
                meta: Meta {
                    arch: Arch::X86,
                    imports,
                    exports,
                    relocs,
                    sections,
                    image_base: nt.OptionalHeader.ImageBase as usize,
                    size_of_image: nt.OptionalHeader.SizeOfImage as usize,
                    entry_pointer: nt.OptionalHeader.AddressOfEntryPoint as usize,
                    file_alignment: nt.OptionalHeader.FileAlignment as usize,
                    section_alignment: nt.OptionalHeader.SectionAlignment as usize,
                    offset_of_nt_header,
                    offset_of_file_header,
                    offset_of_section_header,
                    offset_of_optional_header,
                    size_of_optional_header,
                },
                parse: Box::new(Self(ptr)),
            })
        }
    }
}
