use crate::sp::ServiceProvider;
use chrono::{Duration, SecondsFormat, Utc};
use quick_xml::se::to_string as to_xml_string;
use serde::Serialize;

#[derive(Serialize)]
struct SPSSODescriptor {
    #[serde(rename = "protocolSupportEnumeration")]
    protocol_support_enumeration: String,
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

        to_xml_string(&EntityDescriptor {
            md: "urn:oasis:names:tc:SAML:2.0:metadata".into(),
            ds: "http://www.w3.org/2000/09/xmldsig#".into(),
            entity_id: self.entity_id.to_string(),
            valid_util: tomorrow.to_rfc3339_opts(SecondsFormat::Millis, true),
            sp_sso_descriptor: SPSSODescriptor {
                protocol_support_enumeration:
                    "urn:oasis:names:tc:SAML:1.1:protocol urn:oasis:names:tc:SAML:2.0:protocol"
                        .into(),
            },
        })
        .unwrap()
    }
}
