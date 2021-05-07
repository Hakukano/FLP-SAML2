use openssl::x509::X509;
use std::{fs::read, path::Path};
use url::Url;

use crate::error::Result;

pub mod authn_response;

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
