use std::fs::{create_dir_all, read, File};
use std::path::PathBuf;

use anyhow::{Context, Result};
use internal_russh_forked_ssh_key::LineEnding;
use russh::keys::{encode_pkcs8_pem, load_secret_key, HashAlg, PrivateKey};
use tracing::*;
use warpgate_common::helpers::fs::{secure_directory, secure_file};
use warpgate_common::helpers::rng::get_crypto_rng;
use warpgate_common::{GlobalParams, WarpgateConfig};

fn get_keys_path(config: &WarpgateConfig, params: &GlobalParams) -> PathBuf {
    let mut path = params.paths_relative_to().clone();
    path.push(&config.store.ssh.keys);
    path
}

pub fn generate_keys(config: &WarpgateConfig, params: &GlobalParams, prefix: &str) -> Result<()> {
    let path = get_keys_path(config, params);
    create_dir_all(&path)?;
    if params.should_secure_files() {
        secure_directory(&path)?;
    }

    for (algo, name) in [
        (russh::keys::Algorithm::Ed25519, format!("{prefix}-ed25519")),
        (
            russh::keys::Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
            format!("{prefix}-rsa"),
        ),
    ] {
        let key_path = path.join(name);
        if !key_path.exists() {
            info!("Generating {prefix} key ({algo:?})");
            let key = PrivateKey::random(&mut get_crypto_rng(), algo)
                .context("Failed to generate key")?;
            let f = File::create(&key_path)?;
            encode_pkcs8_pem(&key, f)?;
        }
        if params.should_secure_files() {
            secure_file(&key_path)?;
        }
    }

    Ok(())
}

pub fn load_keys(
    config: &WarpgateConfig,
    params: &GlobalParams,
    prefix: &str,
) -> Result<Vec<PrivateKey>, russh::keys::Error> {
    let path = get_keys_path(config, params);
    Ok(vec![
        load_secret_key(path.join(format!("{prefix}-ed25519")), None)?,
        load_secret_key(path.join(format!("{prefix}-rsa")), None)?,
    ])
}

/// Read raw PEM file contents for the given key prefix (e.g. "client").
/// Returns (filename, contents) for each key file that exists.
pub fn read_key_pem_contents(
    config: &WarpgateConfig,
    params: &GlobalParams,
    prefix: &str,
) -> Result<Vec<(String, Vec<u8>)>> {
    let path = get_keys_path(config, params);
    let mut out = Vec::new();
    for name in [format!("{prefix}-ed25519"), format!("{prefix}-rsa")] {
        let key_path = path.join(&name);
        if key_path.exists() {
            let content = read(&key_path).context("reading key file")?;
            out.push((name, content));
        }
    }
    Ok(out)
}

/// Read client keys and return them in OpenSSH PEM format (LF line endings).
/// Use this for break-glass downloads so OpenSSH and PuTTY accept the keys
/// without "error in libcrypto" that can occur with PKCS#8 PEM from some setups.
/// Returns (filename, openssh_pem_string) for each key.
pub fn read_key_openssh_contents(
    config: &WarpgateConfig,
    params: &GlobalParams,
    prefix: &str,
) -> Result<Vec<(String, String)>, russh::keys::Error> {
    let keys = load_keys(config, params, prefix)?;
    let names = [format!("{prefix}-ed25519"), format!("{prefix}-rsa")];
    let mut out = Vec::with_capacity(keys.len());
    for (key, name) in keys.into_iter().zip(names) {
        let content = key.to_openssh(LineEnding::Lf)?;
        out.push((name, content.as_ref().clone()));
    }
    Ok(out)
}
