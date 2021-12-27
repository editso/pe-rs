mod structs;
pub use crate::structs::*;

mod core;
pub use crate::core::*;

mod error;
pub use crate::error::*;

mod x64;
pub use crate::x64::*;

mod x86;
pub use crate::x86::*;

mod edit;
pub use crate::edit::*;

pub(crate) mod r#macro;

pub mod ffi;

#[cfg(test)]

mod tests {
    use std::io::Read;

    use crate::{ffi, PeParse, X64PE};
    use crate::{PE, X86PE};

    #[test]
    fn test_offset() {
        unsafe {}
    }

    #[test]
    fn test_image() {
        let mut file = std::fs::File::open(r"C:\Windows\System32\User32.dll").unwrap();

        let mut buf = Vec::new();
        file.read_to_end(&mut buf);

        let image = X64PE::to_image(buf.as_mut_ptr()).expect("image");

        unsafe {
            // image.call_entry_pointer();
            let mb = image.get_func("MessageBoxA");

            // 没有修复资源表 调用失败
            let MessageBoxA: extern "C" fn(ffi::LPVOID, ffi::LPCSTR, ffi::LPCSTR, u32) =
                std::mem::transmute(mb);

            MessageBoxA(std::ptr::null_mut(), "Test\0".as_ptr(), "aaa\0".as_ptr(), 1);
        }
    }

    #[test]
    fn test_pe() {
        let mut file = std::fs::File::open(r"C:\Windows\System32\user32.dll").unwrap();
        // let mut file =
        //     std::fs::File::open(r"../fuso/target/i686-pc-windows-msvc/release/fuc.exe").unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf);

        let pe = PE::try_from(buf);

        let pe = pe.expect("parse pe error");

        let edit = pe.edit();

        // println!("size: {}", n);

        // let size = IMAGE_OPTIONAL_HEADER32::size();
    }
}
