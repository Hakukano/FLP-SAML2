# FLP-SAML2

![Crates.io](https://img.shields.io/crates/v/flp-saml2)
![Crates.io](https://img.shields.io/crates/l/flp-saml2)
![Crates.io](https://img.shields.io/crates/d/flp-saml2)

SAML2 for Rust. Mainly used for generating SSO and SLO request, as well as parsing authn response and logout response.

# Signing

For now, requests are always signed. Lib `openssl` is required.

# Optional

For now, `RelayState`, `NameIDFormat` and `AuthnContext` are optional and could be configed while creating `ServiceProvider`

# Testing

Thanks to [kristophjunge/docker-test-saml-idp](https://github.com/kristophjunge/docker-test-saml-idp), I could do a quick test for this library.
