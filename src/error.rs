use std::any::Any;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    InvalidPE,
    Customer(Box<dyn Any>),
}

impl From<&str> for Error {
    fn from(txt: &str) -> Self {
        Self::Customer(Box::new(txt.to_string()))
    }
}
