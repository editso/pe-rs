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

    use crate::ffi;
    use crate::PE;

    #[test]
    fn test_offset() {
        unsafe {
            let ptr = ffi::VirtualAlloc(
                std::mem::zeroed(),
                1024,
                ffi::AllocationType::MEM_COMMIT,
                ffi::Protect::PAGE_EXECUTE_READWRITE,
            );
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

        let a = pe.edit();

        // println!("size: {}", n);

        // let size = IMAGE_OPTIONAL_HEADER32::size();
    }
}
