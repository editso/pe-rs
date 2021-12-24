use crate::*;

pub struct X86PE(*mut u8);

impl PeParse for X86PE {
    fn parse(raw: *mut u8) -> Result<PE> {
        println!("x86");
        unimplemented!()
    }
}
