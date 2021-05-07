use openssl::{error::ErrorStack, x509::X509};
use std::{fmt, fs::read, io, path::Path};
use url::Url;

#[derive(Debug)]
pub enum Error {
    IOError(String),
    InvalidCert(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::IOError(s) => write!(f, "Cannot create SP: {}", s),
            Self::InvalidCert(s) => write!(f, "Cannot create SP: {}", s),
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

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug)]
pub struct IdentityProvider {
    pub login: Url,
    pub logout: Url,
    pub certificates: Vec<X509>,
}

impl IdentityProvider {
    pub fn new(login: Url, logout: Url, certificate_paths: &[&Path]) -> Result<Self> {
        let mut certificates = Vec::with_capacity(certificate_paths.len());
        for certificate_path in certificate_paths {
            certificates.push(X509::from_pem(read(certificate_path)?.as_slice())?);
        }
        Ok(Self {
            login,
            logout,
            certificates,
        })
    }
}
