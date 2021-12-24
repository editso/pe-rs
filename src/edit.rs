use crate::{Result, PE};

pub struct Edit<T> {
    pub(crate) inner: T,
}

impl Edit<PE> {
    pub fn set_entry_pointer(&mut self) -> Result<()> {
        unimplemented!()
    }

    pub fn set_file_alignment(&mut self) -> Result<()> {
        unimplemented!()
    }

    pub fn add_section(&mut self) -> Result<()> {
        unimplemented!()
    }

    pub fn remove_section(&mut self) -> Result<()> {
        unimplemented!()
    }

    pub fn merge_section(&mut self) -> Result<()> {
        unimplemented!()
    }
}
