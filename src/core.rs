use std::{
    collections::HashMap,
    f32::consts::E,
    io::{self, Read},
    iter::TakeWhile,
    ops::Add,
};

use crate::*;

pub enum Arch {
    X86,
    X64,
}

#[allow(unused)]
pub struct Section {
    pub name: String,
    pub virtual_address: usize,
    pub pointer_to_raw_data: usize,
    pub size_of_raw_data: usize,
    pub(crate) offset_of_self: usize,
    pub(crate) raw_ptr: *mut u8,
}

pub struct Reloc {}

#[derive(Debug)]
pub struct Function {
    /// 函数名称
    pub name: String,
    /// 所在偏移
    pub offset_of_self: usize,
}

#[derive(Debug)]
pub struct Oridnal {
    /// 序号
    pub oridnal: usize,
    /// 所在偏移
    pub offset_of_self: usize,
}

#[derive(Debug)]
/// 导入表
pub enum Import {
    /// 以函数名称导入
    Function(Function),
    /// 以序号导入
    Oridnal(Oridnal),
}

/// 导出表
pub enum Export {
    /// 以函数名称导出
    Function(Function),
    /// 以序号导出
    Oridnal(Oridnal),
}

#[allow(unused)]
pub struct Meta {
    arch: Arch,
    /// 导入表信息
    imports: HashMap<String, Vec<Import>>,
    /// 导出表信息
    exports: HashMap<String, Vec<Export>>,
    /// 重定位表信息
    relocs: Vec<Reloc>,
    /// 节表信息
    sections: Vec<Section>,
    /// image base
    image_base: usize,
    /// image 的大小
    size_of_image: usize,
    /// 入口点
    entry_pointer: usize,
    /// 文件对齐
    file_alignment: usize,
    /// 内存对齐
    section_alignment: usize,
    /// nt头的偏移
    offset_of_nt_header: usize,
    /// file头的偏移
    offset_of_file_header: usize,
    /// 可选PE头偏移
    offset_of_section_header: usize,
    /// optional头的偏移
    offset_of_optional_header: usize,
    /// 可选PE头大小
    size_of_optional_header: usize,
}

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
        todo!()
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
                    if iat.u1.Ordinal >> 63 == 1{
                        import_functions.push(Import::Oridnal(
                            Oridnal{
                                offset_of_self: offset,
                                oridnal: (iat.u1.Ordinal & !(0b1 << 63)) as usize
                            }
                        ));
                    }else{
                        let iin = try_as!(IMAGE_IMPORT_BY_NAME, ptr, iat.u1.Function.to_fov(sections)?);

                        let mut name = Vec::new();

                        os_str!(name in iin.Name.as_mut_ptr());

                        import_functions.push(Import::Function(Function{
                            offset_of_self: offset,
                            name: String::from_utf8(name).unwrap(),
                        }));

                    }
                });

                import_map.insert(name, import_functions);
            });
        }

        Ok(import_map)
    }

    fn parse_reloc(_: *mut u8, _: usize) -> Result<Vec<Reloc>>
    where
        Self: Sized,
    {
        unimplemented!()
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
                    raw_ptr: ptr,
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
        let ptr = bytes.as_mut_ptr();
        parse(ptr)
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
