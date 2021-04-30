use openssl::{error::ErrorStack, pkey::Private, rsa::Rsa, x509::X509};
use std::{fmt, fs::read, io, path::Path};
use url::Url;

pub mod metadata;

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
pub struct ServiceProvider {
    pub entity_id: Url,
    pub private_key: Rsa<Private>,
    pub certificate: X509,
    pub assert_login: Url,
    pub assert_logout: Url,
}

impl ServiceProvider {
    pub fn new(
        entity_id: Url,
        private_key_path: &Path,
        certificate_path: &Path,
        assert_login: Url,
        assert_logout: Url,
    ) -> Result<Self> {
        Ok(Self {
            entity_id,
            private_key: Rsa::private_key_from_pem(read(private_key_path)?.as_slice())?,
            certificate: X509::from_pem(read(certificate_path)?.as_slice())?,
            assert_login,
            assert_logout,
        })
    }
}
