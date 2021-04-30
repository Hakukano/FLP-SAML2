use crate::sp::ServiceProvider;
use chrono::{Duration, SecondsFormat, Utc};
use quick_xml::se::to_string as to_xml_string;
use serde::Serialize;

use crate::get_cert_data;

#[derive(Serialize)]
struct AssertionConsumerService {
    #[serde(rename = "Binding")]
    binding: String,
    #[serde(rename = "Location")]
    location: String,
    index: String,
}

#[derive(Serialize)]
struct SingleLogoutService {
    #[serde(rename = "Binding")]
    binding: String,
    #[serde(rename = "Location")]
    location: String,
}

#[derive(Serialize)]
struct X509Certificate {
    #[serde(rename = "$value")]
    value: String,
}

#[derive(Serialize)]
struct X509Data {
    #[serde(rename = "ds:X509Certificate")]
    x509_certificate: X509Certificate,
}

#[derive(Serialize)]
struct KeyInfo {
    #[serde(rename = "xmlns:ds")]
    ds: String,
    #[serde(rename = "ds:X509Data")]
    x509_data: X509Data,
}

#[derive(Serialize)]
struct KeyDescriptor {
    #[serde(rename = "use")]
    us: String,
    #[serde(rename = "ds:KeyInfo")]
    key_info: KeyInfo,
}

#[derive(Serialize)]
struct SPSSODescriptor {
    #[serde(rename = "protocolSupportEnumeration")]
    protocol_support_enumeration: String,
    #[serde(rename = "md:KeyDescriptor")]
    key_descriptor: Vec<KeyDescriptor>,
    #[serde(rename = "md:SingleLogoutService")]
    single_logout_service: SingleLogoutService,
    #[serde(rename = "md:AssertionConsumerService")]
    assertion_consumer_service: AssertionConsumerService,
}

#[derive(Serialize)]
#[serde(rename = "md:EntityDescriptor")]
struct EntityDescriptor {
    #[serde(rename = "xmlns:md")]
    md: String,
    #[serde(rename = "xmlns:ds")]
    ds: String,
    #[serde(rename = "entityID")]
    entity_id: String,
    #[serde(rename = "validUntil")]
    valid_util: String,
    #[serde(rename = "md:SPSSODescriptor")]
    sp_sso_descriptor: SPSSODescriptor,
}

impl ServiceProvider {
    pub fn metadata(&self) -> String {
        let now = Utc::now();
        let tomorrow = now + Duration::days(1);

        let cert_data = get_cert_data(&self.certificate);

        to_xml_string(&EntityDescriptor {
            md: "urn:oasis:names:tc:SAML:2.0:metadata".into(),
            ds: "http://www.w3.org/2000/09/xmldsig#".into(),
            entity_id: self.entity_id.to_string(),
            valid_util: tomorrow.to_rfc3339_opts(SecondsFormat::Millis, true),
            sp_sso_descriptor: SPSSODescriptor {
                protocol_support_enumeration:
                    "urn:oasis:names:tc:SAML:1.1:protocol urn:oasis:names:tc:SAML:2.0:protocol"
                        .into(),
                key_descriptor: vec![
                    KeyDescriptor {
                        us: "signing".into(),
                        key_info: KeyInfo {
                            ds: "http://www.w3.org/2000/09/xmldsig#".into(),
                            x509_data: X509Data {
                                x509_certificate: X509Certificate {
                                    value: cert_data.clone(),
                                },
                            },
                        },
                    },
                    KeyDescriptor {
                        us: "encryption".into(),
                        key_info: KeyInfo {
                            ds: "http://www.w3.org/2000/09/xmldsig#".into(),
                            x509_data: X509Data {
                                x509_certificate: X509Certificate { value: cert_data },
                            },
                        },
                    },
                ],
                single_logout_service: SingleLogoutService {
                    binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect".into(),
                    location: self.assert_logout.to_string(),
                },
                assertion_consumer_service: AssertionConsumerService {
                    binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".into(),
                    location: self.assert_login.to_string(),
                    index: "0".into(),
                },
            },
        })
        .unwrap()
    }
}
