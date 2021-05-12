use openssl::x509::X509;
use quick_xml::de::from_str as from_xml_str;
use serde::Deserialize;

use crate::{
    error::{Error, Result},
    idp::IdentityProvider,
};

#[derive(Deserialize)]
pub struct AttributeValue {
    #[serde(rename = "xsi:type")]
    pub typ: String,
    #[serde(rename = "$value")]
    pub value: String,
}

#[derive(Deserialize)]
pub struct Attribute {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "NameFormat")]
    pub name_format: String,
    #[serde(rename = "saml:AttributeValue")]
    pub attribute_values: Vec<AttributeValue>,
}

#[derive(Deserialize)]
pub struct AttributeStatement {
    #[serde(rename = "saml:Attribute")]
    pub attributes: Vec<Attribute>,
}

#[derive(Deserialize)]
pub struct AuthnContextClassRef {
    #[serde(rename = "$value")]
    pub value: String,
}

#[derive(Deserialize)]
pub struct AuthnContext {
    #[serde(rename = "saml:AuthnContextClassRef")]
    pub authn_context_class_ref: AuthnContextClassRef,
}

#[derive(Deserialize)]
pub struct AuthnStatement {
    #[serde(rename = "AuthnInstant")]
    pub authn_instant: String,
    #[serde(rename = "SessionNotOnOrAfter")]
    pub session_not_on_or_after: String,
    #[serde(rename = "SessionIndex")]
    pub session_index: String,
    #[serde(rename = "saml:AuthnContext")]
    pub authn_context: AuthnContext,
}

#[derive(Deserialize)]
pub struct Audience {
    #[serde(rename = "$value")]
    pub value: String,
}

#[derive(Deserialize)]
pub struct AudienceRestriction {
    #[serde(rename = "saml:Audience")]
    pub audience: Audience,
}

#[derive(Deserialize)]
pub struct Conditions {
    #[serde(rename = "NotBefore")]
    pub not_before: String,
    #[serde(rename = "NotOnOrAfter")]
    pub not_on_or_after: String,
    #[serde(rename = "saml:AudienceRestriction")]
    pub audience_restriction: AudienceRestriction,
}

#[derive(Deserialize)]
pub struct SubjectConfirmationData {
    #[serde(rename = "NotOnOrAfter")]
    pub not_on_or_after: String,
    #[serde(rename = "Recipient")]
    pub recipient: String,
    #[serde(rename = "InResponseTo")]
    pub in_response_to: String,
}

#[derive(Deserialize)]
pub struct SubjectConfirmation {
    #[serde(rename = "Method")]
    pub method: String,
    #[serde(rename = "saml:SubjectConfirmationData")]
    pub subject_confirmation_data: SubjectConfirmationData,
}

#[derive(Deserialize)]
pub struct NameID {
    #[serde(rename = "SPNameQualifier")]
    pub sp_name_qualifier: String,
    #[serde(rename = "Format")]
    pub format: String,
    #[serde(rename = "$value")]
    pub value: String,
}

#[derive(Deserialize)]
pub struct Subject {
    #[serde(rename = "saml:NameID")]
    pub name_id: NameID,
    #[serde(rename = "saml:SubjectConfirmation")]
    pub subject_confirmation: SubjectConfirmation,
}

#[derive(Deserialize)]
pub struct StatusCode {
    #[serde(rename = "Value")]
    pub value: String,
}

#[derive(Deserialize)]
pub struct Status {
    #[serde(rename = "samlp:StatusCode")]
    pub status_code: StatusCode,
}

#[derive(Deserialize)]
pub struct X509Certificate {
    #[serde(rename = "$value")]
    pub value: String,
}

#[derive(Deserialize)]
pub struct X509Data {
    #[serde(rename = "ds:X509Certificate")]
    pub x509_certificate: X509Certificate,
}

#[derive(Deserialize)]
pub struct KeyInfo {
    #[serde(rename = "xmlns:ds")]
    pub ds: String,
    #[serde(rename = "ds:X509Data")]
    pub x509_data: X509Data,
}

#[derive(Deserialize)]
pub struct SignatureValue {
    #[serde(rename = "$value")]
    pub value: String,
}

#[derive(Deserialize)]
pub struct DigestValue {
    #[serde(rename = "$value")]
    pub value: String,
}

#[derive(Deserialize)]
pub struct DigestMethod {
    #[serde(rename = "Algorithm")]
    pub algorithm: String,
}

#[derive(Deserialize)]
pub struct Transform {
    #[serde(rename = "Algorithm")]
    pub algorithm: String,
}

#[derive(Deserialize)]
pub struct Transforms {
    #[serde(rename = "ds:Transform")]
    pub transforms: Vec<Transform>,
}

#[derive(Deserialize)]
pub struct Reference {
    #[serde(rename = "URI")]
    pub uri: String,
    #[serde(rename = "ds:Transforms")]
    pub transforms: Transforms,
    #[serde(rename = "ds:DigestMethod")]
    pub digest_method: DigestMethod,
    #[serde(rename = "ds:DigestValue")]
    pub digest_value: DigestValue,
}

#[derive(Deserialize)]
pub struct SignatureMethod {
    #[serde(rename = "Algorithm")]
    pub algorithm: String,
}

#[derive(Deserialize)]
pub struct CanonicalizationMethod {
    #[serde(rename = "Algorithm")]
    pub algorithm: String,
}

#[derive(Deserialize)]
pub struct SignedInfo {
    #[serde(rename = "ds:CanonicalizationMethod")]
    pub canonicalization_method: CanonicalizationMethod,
    #[serde(rename = "ds:SignatureMethod")]
    pub signature_method: SignatureMethod,
    #[serde(rename = "ds:Reference")]
    pub reference: Reference,
}

#[derive(Deserialize)]
pub struct Signature {
    #[serde(rename = "ds:SignedInfo")]
    pub signed_info: SignedInfo,
    #[serde(rename = "ds:SignatureValue")]
    pub signature_value: SignatureValue,
    #[serde(rename = "ds:KeyInfo")]
    pub key_info: KeyInfo,
}

#[derive(Deserialize)]
pub struct Issuer {
    #[serde(rename = "$value")]
    pub value: String,
}

#[derive(Deserialize)]
pub struct Assertion {
    #[serde(rename = "xmlns:xsi")]
    pub xsi: String,
    #[serde(rename = "xmlns:xs")]
    pub xs: String,
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "IssueInstant")]
    pub issue_instant: String,
    #[serde(rename = "saml:Issuer")]
    pub issuer: Issuer,
    #[serde(rename = "ds:Signature")]
    pub signature: Option<Signature>,
    #[serde(rename = "saml:Subject")]
    pub subject: Subject,
    #[serde(rename = "saml:Conditions")]
    pub conditions: Conditions,
    #[serde(rename = "saml:AuthnStatement")]
    pub authn_statement: AuthnStatement,
    #[serde(rename = "saml:AttributeStatement")]
    pub attribute_statement: AttributeStatement,
}

#[derive(Deserialize)]
#[serde(rename = "samlp:Response")]
pub struct Response {
    #[serde(rename = "xmlns:samlp")]
    pub samlp: String,
    #[serde(rename = "xmlns:saml")]
    pub saml: String,
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "IssueInstant")]
    pub issue_instant: String,
    #[serde(rename = "Destination")]
    pub destination: String,
    #[serde(rename = "InResponseTo")]
    pub in_response_to: String,
    #[serde(rename = "saml:Issuer")]
    pub issuer: Issuer,
    #[serde(rename = "ds:Signature")]
    pub signature: Option<Signature>,
    #[serde(rename = "samlp:Status")]
    pub status: Status,
    #[serde(rename = "saml:Assertion")]
    pub assertion: Assertion,
}

impl IdentityProvider {
    pub fn authn_response(&self, xml: &str) -> Result<Response> {
        let response = from_xml_str::<Response>(xml)?;
        if let Some(signature) = response.signature.as_ref() {
            let cert = X509::from_pem(
                signature
                    .key_info
                    .x509_data
                    .x509_certificate
                    .value
                    .as_bytes(),
            )?;
            let mut is_valid = false;
            for public_key in self.certificates.iter() {
                if cert.verify(public_key.public_key()?.as_ref())? {
                    is_valid = true;
                    break;
                }
            }
            if !is_valid {
                return Err(Error::InvalidCert(
                    "SAML response contains invalid cert".into(),
                ));
            }
        }
        Ok(response)
    }
}
