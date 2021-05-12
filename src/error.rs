use openssl::error::ErrorStack;
use quick_xml::DeError;
use std::{fmt, io};

#[derive(Debug)]
pub enum Error {
    IOError(String),
    InvalidCert(String),
    InvalidResponse(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::IOError(s) => write!(f, "Cannot create SP: {}", s),
            Self::InvalidCert(s) => write!(f, "Cannot create SP: {}", s),
            Self::InvalidResponse(s) => write!(f, "Cannot create SP: {}", s),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::IOError(err.to_string())
    }
}

impl From<ErrorStack> for Error {
    fn from(err: ErrorStack) -> Self {
        Self::InvalidCert(err.to_string())
    }
}

impl From<DeError> for Error {
    fn from(err: DeError) -> Self {
        Self::InvalidResponse(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
