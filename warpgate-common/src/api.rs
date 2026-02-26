use http::StatusCode;
use poem::{FromRequest, Request, RequestBody};
use poem_openapi::auth::ApiKey;
use poem_openapi::SecurityScheme;

#[derive(SecurityScheme)]
#[oai(ty = "api_key", key_name = "X-Warpgate-Token", key_in = "header")]
#[allow(dead_code)]
pub struct TokenSecurityScheme(ApiKey);

#[derive(SecurityScheme)]
#[oai(ty = "api_key", key_name = "warpgate-http-session", key_in = "cookie")]
#[allow(dead_code)]
pub struct CookieSecurityScheme(ApiKey);

#[derive(SecurityScheme)]
#[allow(dead_code)]
pub enum AnySecurityScheme {
    Token(TokenSecurityScheme),
    Cookie(CookieSecurityScheme),
}

/// Identity of the admin user for the current request. Set by HTTP layer when admin auth succeeds.
#[derive(Clone, Debug)]
pub struct AdminIdentity {
    /// Username when authenticated as a user; None when using admin token.
    pub username: Option<String>,
}

#[poem::async_trait]
impl FromRequest for AdminIdentity {
    async fn from_request(req: &Request, _body: &mut RequestBody) -> poem::Result<Self> {
        req.extensions()
            .get::<AdminIdentity>()
            .cloned()
            .ok_or_else(|| poem::Error::from_status(StatusCode::UNAUTHORIZED))
    }
}
