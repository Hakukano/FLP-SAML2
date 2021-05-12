use flp_saml2::{idp::IdentityProvider, sp::ServiceProvider};
use std::path::Path;
#[cfg(test)]
use tokio::runtime::Runtime;
use url::Url;

const SP_ENTITY: &str = "http://1.2.3/entity";
const SP_LOGIN: &str = "http://1.2.3/login";
const SP_LOGOUT: &str = "http://1.2.3/logout";
const IDP_LOGIN: &str = "https://a.b.c/login";
const IDP_LOGOUT: &str = "https://a.b.c/logout";

#[test]
fn test_login() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let handle = tokio::spawn(async move {
            let idp = IdentityProvider::new(
                Url::parse(IDP_LOGIN).unwrap(),
                Url::parse(IDP_LOGOUT).unwrap(),
                &[&Path::new("./certs/idp.crt")],
            )
            .unwrap();
            let sp = ServiceProvider::new(
                Url::parse(SP_ENTITY).unwrap(),
                Path::new("./certs/sp.key"),
                Path::new("./certs/sp.crt"),
                Url::parse(SP_LOGIN).unwrap(),
                Url::parse(SP_LOGOUT).unwrap(),
            )
            .unwrap();
            let resp = reqwest::get(sp.authn_redirect(&idp).unwrap())
                .await
                .unwrap()
                .text()
                .await
                .unwrap();
            println!("{}", resp);
        });
        let _ = tokio::join!(handle);
    });
}
