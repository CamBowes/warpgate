use std::collections::HashSet;

use openidconnect::url::Url;
use openidconnect::{CsrfToken, Nonce, PkceCodeVerifier, RedirectUrl};
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::{SsoClient, SsoError, SsoInternalProviderConfig, SsoLoginResponse};

/// Extract "roles" and "groups" from ID token JWT payload (already verified by openidconnect).
/// Used so role_mappings apply to Entra "roles" (app roles) and "groups" (group object IDs).
fn extract_roles_groups_from_id_token(token_str: &str) -> (Option<Vec<String>>, Option<Vec<String>>) {
    let parts: Vec<&str> = token_str.splitn(3, '.').collect();
    let payload_b64 = match parts.get(1) {
        Some(p) => *p,
        None => return (None, None),
    };
    // JWT uses base64url (- and _); convert to standard base64 (+ and /) and add padding
    let base64_std: String = payload_b64
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    let pad_len = (4 - base64_std.len() % 4) % 4;
    let padded = format!("{}{}", base64_std, "=".repeat(pad_len));
    let bytes = match data_encoding::BASE64.decode(padded.as_bytes()) {
        Ok(b) => b,
        Err(_) => return (None, None),
    };
    let payload: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return (None, None),
    };
    let roles = payload
        .get("roles")
        .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok())
        .or_else(|| {
            payload.get("roles").and_then(|v| {
                v.as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|x| x.as_str().map(String::from))
                            .collect::<Vec<_>>()
                    })
                    .filter(|v: &Vec<String>| !v.is_empty())
            })
        });
    let groups = payload
        .get("groups")
        .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok())
        .or_else(|| {
            payload.get("groups").and_then(|v| {
                v.as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|x| {
                                x.as_str()
                                    .map(String::from)
                                    .or_else(|| x.as_u64().map(|n| n.to_string()))
                            })
                            .collect::<Vec<_>>()
                    })
                    .filter(|v: &Vec<String>| !v.is_empty())
            })
        });
    (roles, groups)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SsoLoginRequest {
    pub(crate) auth_url: Url,
    pub(crate) csrf_token: CsrfToken,
    pub(crate) nonce: Nonce,
    pub(crate) redirect_url: RedirectUrl,
    pub(crate) pkce_verifier: Option<PkceCodeVerifier>,
    pub(crate) config: SsoInternalProviderConfig,
}

impl SsoLoginRequest {
    pub fn auth_url(&self) -> &Url {
        &self.auth_url
    }

    pub fn csrf_token(&self) -> &CsrfToken {
        &self.csrf_token
    }

    pub fn redirect_url(&self) -> &RedirectUrl {
        &self.redirect_url
    }

    pub async fn verify_code(self, code: String) -> Result<SsoLoginResponse, SsoError> {
        let result = SsoClient::new(self.config)?
            .finish_login(self.pkce_verifier, self.redirect_url, &self.nonce, code)
            .await?;

        debug!("OIDC claims: {:?}", result.claims);
        debug!("OIDC userinfo claims: {:?}", result.userinfo_claims);

        macro_rules! get_claim {
            ($method:ident) => {
                result
                    .claims
                    .$method()
                    .or(result.userinfo_claims.as_ref().and_then(|x| x.$method()))
            };
        }

        // If preferred_username is absent, fall back to `email`
        let preferred_username = get_claim!(preferred_username)
            .map(|x| x.as_str())
            .map(ToString::to_string)
            .or_else(|| {
                get_claim!(email)
                    .map(|x| x.as_str())
                    .map(ToString::to_string)
            });

        Ok(SsoLoginResponse {
            preferred_username,

            name: get_claim!(name)
                .and_then(|x| x.get(None))
                .map(|x| x.as_str())
                .map(ToString::to_string),

            email: get_claim!(email)
                .map(|x| x.as_str())
                .map(ToString::to_string),

            email_verified: get_claim!(email_verified),

            groups: {
                let ac = result.userinfo_claims.as_ref().map(|x| x.additional_claims());
                let warpgate_roles = ac.and_then(|c| c.warpgate_roles.clone());
                let userinfo_roles = ac.and_then(|c| c.roles.clone());
                let userinfo_groups = ac.and_then(|c| c.groups.clone());
                let (id_roles, id_groups) =
                    extract_roles_groups_from_id_token(&result.token.to_string());
                let mut all: Vec<String> = Vec::new();
                for v in [
                    warpgate_roles,
                    userinfo_roles,
                    userinfo_groups,
                    id_roles,
                    id_groups,
                ] {
                    if let Some(vec) = v {
                        all.extend(vec);
                    }
                }
                let mut seen = HashSet::new();
                let mut dedup = Vec::new();
                for s in all {
                    if seen.insert(s.clone()) {
                        dedup.push(s);
                    }
                }
                if dedup.is_empty() {
                    None
                } else {
                    Some(dedup)
                }
            },

            id_token: result.token.clone(),
        })
    }
}
