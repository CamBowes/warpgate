use std::sync::Arc;

use chrono::Utc;
use poem::web::Data;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, DatabaseConnection};
use serde::Serialize;
use tokio::sync::Mutex;
use uuid::Uuid;
use warpgate_common::api::AdminIdentity;
use warpgate_common::WarpgateError;
use warpgate_core::Services;
use warpgate_db_entities::LogEntry;

use super::AnySecurityScheme;

pub struct Api;

#[derive(Serialize, Object)]
struct BreakGlassKey {
    pub filename: String,
    /// PEM content as UTF-8 string.
    pub content: String,
}

#[derive(Serialize, Object)]
struct BreakGlassKeysResponse {
    pub keys: Vec<BreakGlassKey>,
    pub readme: String,
}

#[derive(ApiResponse)]
enum GetBreakGlassKeysResponse {
    #[oai(status = 200)]
    Ok(Json<BreakGlassKeysResponse>),
}

const README_TEXT: &str = r#"Warpgate break-glass SSH keys
============================

Use these keys ONLY in an emergency when Warpgate is unavailable, to connect directly to targets. Store them securely. Each download is logged.

OpenSSH / terminal
------------------
1. Save each key file (e.g. client-ed25519, client-rsa) to a secure location.
2. Set permissions: chmod 600 <keyfile>
3. Connect: ssh -i <keyfile> <user>@<target_host>

PuTTY (Windows)
---------------
Keys are in PEM format. Convert to PuTTY's .ppk format:
1. Open PuTTYgen
2. Conversions → Import key → select the PEM file
3. Save private key (as .ppk)
4. In PuTTY: Connection → SSH → Auth → Private key file → select the .ppk
   Or load the .ppk into Pageant.
5. Connect as usual to the target host.

Rotating keys after a breach (avoiding lockout)
-----------------------------------------------
Do NOT remove old keys from targets until new keys are in place and verified.
Order of operations:

1. On the Warpgate server: back up then delete the client key files
   (e.g. client-ed25519 and client-rsa in your SSH keys directory).
2. Restart Warpgate so it generates new client keys.
3. Get the NEW public keys:
   - CLI: warpgate client-keys
   - Or in Admin UI: Targets → configure a target → SSH → "Warpgate's own private keys" / view own keys.
4. Add the NEW public keys to authorized_keys on EVERY target that uses them.
   Keep the old public keys in place for now.
5. Verify access: download break-glass keys from this page and test
   ssh -i <new-keyfile> <user>@<target> for at least one target.
6. Remove the OLD public keys from authorized_keys on all targets.
7. Securely destroy old private key copies (this download, backups, any stored break-glass keys).
"#;

#[OpenApi]
impl Api {
    #[oai(
        path = "/ssh/break-glass-keys",
        method = "get",
        operation_id = "get_ssh_break_glass_keys"
    )]
    async fn api_ssh_get_break_glass_keys(
        &self,
        admin_identity: Data<&AdminIdentity>,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        services: Data<&Services>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetBreakGlassKeysResponse, WarpgateError> {
        let config = services.config.lock().await;
        // Serve keys in OpenSSH PEM format with LF line endings so OpenSSH and PuTTY
        // accept them (PKCS#8 PEM can cause "Load key: error in libcrypto" on some setups).
        let keys = warpgate_protocol_ssh::read_key_openssh_contents(
            &config,
            &services.global_params,
            "client",
        )?;

        let username = admin_identity
            .username
            .clone()
            .unwrap_or_else(|| "admin-token".to_string());

        let log_entry = LogEntry::ActiveModel {
            id: Set(Uuid::new_v4()),
            text: Set("Break-glass SSH keys downloaded".to_string()),
            values: Set(serde_json::json!({"action": "break_glass_keys_download"})),
            timestamp: Set(Utc::now()),
            session_id: Set(Uuid::nil()),
            username: Set(Some(username)),
        };

        let db_guard = db.lock().await;
        log_entry.insert(&*db_guard).await?;
        drop(db_guard);

        let keys: Vec<BreakGlassKey> = keys
            .into_iter()
            .map(|(filename, content)| BreakGlassKey { filename, content })
            .collect();

        Ok(GetBreakGlassKeysResponse::Ok(Json(BreakGlassKeysResponse {
            keys,
            readme: README_TEXT.to_string(),
        })))
    }
}
