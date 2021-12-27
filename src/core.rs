use std::{any::Any, collections::HashMap, fmt::Debug};

use crate::*;

#[derive(Debug)]
pub enum Arch {
    X86,
    X64,
}

#[allow(unused)]
#[derive(Debug)]
pub struct Section {
    pub name: String,
    pub virtual_address: usize,
    pub pointer_to_raw_data: usize,
    pub size_of_raw_data: usize,
    pub offset_of_self: usize,
}

#[allow(unused)]
#[derive(Debug)]
pub struct Reloc {
    /// rva 基础偏移
    base_of_rva_offset: usize,
    /// fov 基础偏移
    base_of_fov_offset: usize,
    /// 相对基础偏移, 所有需要修复的地址
    /// Reloc.base_offset + reloc_offset = 真实需要修复的地址
    reloc_offsets: Vec<(u8, WORD, ULONGLONG)>,
    /// 重定位表 fov 地址
    offset_of_fov: usize,
}

#[derive(Debug)]
pub struct Name {
    /// 函数名称
    pub name: String,
    /// 所在偏移 fov
    pub offset_of_address: usize,
    /// 序号
    pub ordinal: Option<usize>,
}

#[derive(Debug)]
pub struct Ordinal {
    /// 序号
    pub ordinal: usize,
    /// 所在偏移
    pub offset_of_address: usize,
}

#[derive(Debug)]
/// 导入表
pub enum Import {
    /// 以函数名称导入
    ByName(Name),
    /// 以序号导入
    ByOrdinal(Ordinal),
}

#[derive(Debug)]
/// 导出表
pub enum Export {
    /// 以函数名称导出
    ByName(Name),
    /// 以序号导出
    ByOrdinal(Ordinal),
}

#[allow(unused)]
#[derive(Debug)]
pub struct Meta {
    pub arch: Arch,
    /// 导入表信息
    pub imports: HashMap<String, Vec<Import>>,
    /// 导出表信息
    pub exports: Vec<Export>,
    /// 重定位表信息
    pub relocs: Vec<Reloc>,
    /// 节表信息
    pub sections: Vec<Section>,
    /// image base
    pub image_base: usize,
    /// image 的大小
    pub size_of_image: usize,
    /// 入口点
    pub entry_pointer: usize,
    /// 文件对齐
    pub file_alignment: usize,
    /// 内存对齐
    pub section_alignment: usize,
    /// nt头的偏移
    pub offset_of_nt_header: usize,
    /// file头的偏移
    pub offset_of_file_header: usize,
    /// 可选PE头偏移
    pub offset_of_section_header: usize,
    /// optional头的偏移
    pub offset_of_optional_header: usize,
    /// 可选PE头大小
    pub size_of_optional_header: usize,
}

#[allow(unused)]
pub struct PE {
    pub(crate) meta: Meta,
    pub(crate) parse: Box<dyn PeParse>,
}

pub trait ToFov {
    fn to_fov(&self, sections: &[Section]) -> Result<usize>;
}

impl ToFov for usize {
    fn to_fov(&self, sections: &[Section]) -> Result<usize> {
        for section in sections {
            if section.virtual_address <= *self
                && section.size_of_raw_data + section.virtual_address >= *self
            {
                return Ok(*self - section.virtual_address + section.pointer_to_raw_data);
            }
        }

        Err(Error::InvalidPE)
    }
}

impl ToFov for u32 {
    fn to_fov(&self, sections: &[Section]) -> Result<usize> {
        (*self as usize).to_fov(sections)
    }
}

impl ToFov for u64 {
    fn to_fov(&self, sections: &[Section]) -> Result<usize> {
        (*self as usize).to_fov(sections)
    }
}

pub trait PeParse {
    fn parse_exports(
        ptr: *mut u8,
        sections: &[Section],
        virtual_address: usize,
    ) -> Result<Vec<Export>>
    where
        Self: Sized,
    {
        let mut exports = Vec::new();

        unsafe {
            let export = try_as!(
                IMAGE_EXPORT_DIRECTORY,
                ptr,
                virtual_address.to_fov(sections)?
            );

            let number_of_functions = export.NumberOfFunctions as usize;

            // 所有导出的函数 按序号导出 + 按名称导出
            let export_of_functions = std::slice::from_raw_parts(
                ptr.add(export.AddressOfFunctions.to_fov(sections)?) as *const DWORD,
                number_of_functions,
            );

            // 按序号导出的函数
            let export_of_ordinals = std::slice::from_raw_parts(
                ptr.add(export.AddressOfNameOrdinals.to_fov(sections)?) as *const WORD,
                export.NumberOfFunctions as usize,
            );

            // 按名称导出的函数
            let export_by_names = std::slice::from_raw_parts(
                ptr.add(export.AddressOfNames.to_fov(sections)?) as *const DWORD,
                export.NumberOfFunctions as usize,
            );

            for i in 0..number_of_functions {
                let mut j = 0;

                while j < export.NumberOfNames as usize {
                    if i == export_of_ordinals[j] as usize {
                        break;
                    }
                    j += 1;
                }

                let export = if j < export.NumberOfNames as usize {
                    // 按名称导出

                    let mut name = Vec::new();

                    os_str!(name in  ptr.add(export_by_names[j].to_fov(sections)?));

                    Export::ByName(Name {
                        name: String::from_utf8(name).unwrap(),
                        offset_of_address: export_of_functions[i] as usize,
                        ordinal: Some(export.Base as usize + export_of_ordinals[j] as usize),
                    })
                } else {
                    // 按序号导出
                    Export::ByOrdinal(Ordinal {
                        ordinal: i + export.Base as usize,
                        offset_of_address: export_of_functions[i] as usize,
                    })
                };

                exports.push(export);
            }
        }

        Ok(exports)
    }
    
    /// 解析导入表
    /// 默认解析64位PE文件
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
                    IMAGE_THUNK_DATA64,
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
                    let import = if iat.u1.Ordinal >> 63 == 1{
                        Import::ByOrdinal(
                            Ordinal{
                                offset_of_address: offset,
                                ordinal: (iat.u1.Ordinal & !(0b1 << 63)) as usize
                            }
                        )
                    }else{
                        let iin = try_as!(IMAGE_IMPORT_BY_NAME, ptr, iat.u1.Function.to_fov(sections)?);

                        let mut name = Vec::new();

                        os_str!(name in iin.Name.as_mut_ptr());

                        Import::ByName(Name{
                            ordinal: None,
                            offset_of_address: offset,
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

    /// 解析重定位表
    fn parse_reloc(ptr: *mut u8, sections: &[Section], virtual_address: usize) -> Result<Vec<Reloc>>
    where
        Self: Sized,
    {
        // 解析好后的重定位表信息
        let mut relocs = Vec::new();

        unsafe {
            // 拿到第一个重定位表
            let mut reloc_ptr = try_ptr!(
                IMAGE_BASE_RELOCATION,
                ptr,
                virtual_address.to_fov(sections)?
            );

            loop {
                if reloc_ptr.is_null() {
                    return Err(Error::InvalidPE);
                }

                // 相对 ptr 的偏移量
                let offset = reloc_ptr as usize - ptr as usize;

                let reloc = reloc_ptr.as_ref().unwrap();

                // 如果重定位表任意字段都为0代表重定位表结束
                if reloc.VirtualAddress == 0 {
                    break;
                }

                // 整个块中需要重定位的总数量
                // 这个总数量是不准确的
                // 高4如果不为0则代表需要重定位
                let reloc_num = (reloc.SizeOfBlock as usize - IMAGE_BASE_RELOCATION::size()) / 2;

                // 指向第一个需要重定位的偏移
                let relocs_ptr = ptr.add(offset + IMAGE_BASE_RELOCATION::size()) as *const WORD;

                // 所有需要重定位偏移
                let reloc_offsets = std::slice::from_raw_parts(relocs_ptr, reloc_num)
                    .iter()
                    .fold(Vec::new(), |mut relocs, e| {
                        let typ = e >> 12;

                        (typ == 10 || typ == 3).then(|| {
                            // 真实偏移量是低12位
                            let offset = e & 0xFFF;

                            let value_offset = (reloc.VirtualAddress as usize + offset as usize)
                                .to_fov(sections)
                                .unwrap();

                            let value_offset_ptr = ptr.add(value_offset);

                            let value_offset = typ
                                .eq(&10)
                                .then(|| *(value_offset_ptr as *const ULONGLONG).as_ref().unwrap())
                                .unwrap_or(*(value_offset_ptr as *const DWORD).as_ref().unwrap()
                                    as ULONGLONG);

                            relocs.push((typ as u8, offset, value_offset));
                        });

                        relocs
                    });

                let base_of_fov_offset = reloc.VirtualAddress.to_fov(sections)?;

                relocs.push(Reloc {
                    reloc_offsets,
                    base_of_fov_offset,
                    offset_of_fov: offset,
                    base_of_rva_offset: reloc.VirtualAddress as usize,
                });

                // 指向下一个需要重定位的表
                // ptr + IMAGE_BASE_RELOCATION + IMAGE_BASE_RELOCATION.SizeOfBlock = 下一个重定位表
                reloc_ptr = try_ptr!(
                    IMAGE_BASE_RELOCATION,
                    ptr,
                    offset + reloc.SizeOfBlock as usize
                );
            }
        }

        Ok(relocs)
    }

    /// 解析节表
    fn parse_section(
        ptr: *mut u8,
        number_of_section: usize,
        offset_of_section_header: usize,
    ) -> Result<Vec<Section>>
    where
        Self: Sized,
    {
        let mut sections = Vec::new();

        unsafe {
            let first_section = try_ptr!(IMAGE_SECTION_HEADER, ptr, offset_of_section_header);

            for i in 0..number_of_section {
                let section = first_section.add(i);

                if section.is_null() {
                    return Err(Error::InvalidPE);
                }

                let offset_of_self = section as usize - ptr as usize;

                let section = section.as_ref().unwrap();

                let mut name = Vec::new();

                os_str!(name in section.Name.as_ptr());

                let section = Section {
                    name: String::from_utf8(name).unwrap(),
                    offset_of_self,
                    virtual_address: section.VirtualAddress as usize,
                    pointer_to_raw_data: section.PointerToRawData as usize,
                    size_of_raw_data: section.SizeOfRawData as usize,
                };

                sections.push(section);
            }
        }

        Ok(sections)
    }

    fn parse(_: *mut u8) -> Result<PE>
    where
        Self: Sized,
    {
        unimplemented!()
    }
}

pub fn parse(raw: *mut u8) -> Result<PE> {
    unsafe {
        IMAGE_DOS_HEADER::from_bytes(raw)
            .as_ref()
            .and_then(|dos| {
                let e_lfanew = dos.e_lfanew as isize;
                IMAGE_NT_HEADERS::from_bytes(raw.offset(e_lfanew)).as_ref()
            })
            .and_then(|nt| {
                nt.Signature
                    .eq(&IMAGE_NT_SIGNATURE)
                    .then(|| nt.OptionalHeader.Magic)
            })
            .map_or_else(
                || Err(Error::InvalidPE),
                |arch| match arch {
                    IMAGE_NT_OPTIONAL_HDR32_MAGIC => X86PE::parse(raw),
                    IMAGE_NT_OPTIONAL_HDR64_MAGIC => X64PE::parse(raw),
                    _ => Err(Error::InvalidPE),
                },
            )
    }
}

impl PE {
    pub(crate) fn from_bytes(bytes: &mut [u8]) -> Result<Self> {
        parse(bytes.as_mut_ptr())
    }

    pub fn edit(self) -> Edit<PE> {
        Edit { inner: self }
    }
}

impl TryFrom<&mut [u8]> for PE {
    type Error = Error;

    fn try_from(bytes: &mut [u8]) -> Result<Self> {
        Self::from_bytes(bytes)
    }
}

impl TryFrom<Vec<u8>> for PE {
    type Error = Error;

    fn try_from(mut data: Vec<u8>) -> Result<Self> {
        Self::from_bytes(&mut data)
    }
}

impl Debug for PE {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PE")
            .field("meta", &self.meta)
            .field("parse", &self.parse.type_id())
            .finish()
    }
}
