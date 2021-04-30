use lazy_static::lazy_static;
use openssl::x509::X509;
use regex::Regex;

pub mod idp;
pub mod sp;

lazy_static! {
    static ref REGEX_CERTIFICATE: Regex =
        Regex::new(r#"-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----"#).unwrap();
}

pub fn get_cert_data(cert: &X509) -> String {
    for capture in
        REGEX_CERTIFICATE.captures_iter(&String::from_utf8(cert.to_pem().unwrap()).unwrap())
    {
        return capture[1].into();
    }
    String::new()
}
