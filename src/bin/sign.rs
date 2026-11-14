//! Offline signing helper for `on-device`.
//!
//! ```text
//! sign keygen [secret-path]
//!     Generate a keypair. Without `secret-path`, prints `secret: <hex>` and
//!     `public: <hex>`. With it, writes the secret to that file (mode 0600) and
//!     prints only `public: <hex>` so the secret never reaches the terminal.
//!     Put `public` in `.env` as `SIGNING_PUBKEY=` and rebuild, then keep
//!     `secret` offline.
//!
//! sign sign <binary> <secret-hex|secret-file>
//!     Write `<binary>.sig` (hex Ed25519 signature) for the given binary. The
//!     secret may be given inline or as a path to a file holding the hex.
//!
//! sign verify <binary> <public-hex>
//!     Verify `<binary>` against `<binary>.sig` (no secret needed).
//! ```
//!
//! Not linked into the shipped binary: it exists only on the signing host.

use std::path::Path;
use std::process::ExitCode;

use ed25519_dalek::{Signer, SigningKey};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let result = match args.get(1).map(String::as_str) {
        Some("keygen") => keygen(args.get(2)),
        Some("sign") => sign(args.get(2), args.get(3)),
        Some("verify") => verify(args.get(2), args.get(3)),
        _ => Err(usage()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::FAILURE
        }
    }
}

fn usage() -> String {
    "usage:\n  sign keygen [secret-path]\n  sign sign <binary> <secret-hex>\n  sign verify <binary> <public-hex>"
        .to_string()
}

fn keygen(secret_path: Option<&String>) -> Result<(), String> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| format!("csprng failure: {e}"))?;
    let signing_key = SigningKey::from_bytes(&seed);
    let secret_hex = hex::encode(signing_key.to_bytes());
    let public_hex = hex::encode(signing_key.verifying_key().to_bytes());

    match secret_path {
        Some(path) => {
            write_secret(path, &format!("{secret_hex}\n"))?;
            println!("public: {public_hex}");
            println!("secret written to {path}");
        }
        None => {
            println!("secret: {secret_hex}");
            println!("public: {public_hex}");
        }
    }
    Ok(())
}

/// Write a secret file with owner-only permissions where supported.
fn write_secret(path: &str, contents: &str) -> Result<(), String> {
    use std::io::Write;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| format!("cannot create {path}: {e}"))?;
    file.write_all(contents.as_bytes())
        .map_err(|e| format!("cannot write {path}: {e}"))?;
    Ok(())
}

fn sign(binary: Option<&String>, secret_hex: Option<&String>) -> Result<(), String> {
    let (binary, secret_hex) = match (binary, secret_hex) {
        (Some(b), Some(s)) => (b, s),
        _ => return Err(usage()),
    };

    let seed = read_secret(secret_hex)?;
    let signing_key = SigningKey::from_bytes(&seed);

    let data = std::fs::read(binary).map_err(|e| format!("cannot read {binary}: {e}"))?;
    let signature = signing_key.sign(&data);

    let sig_path = format!("{binary}.sig");
    std::fs::write(&sig_path, hex::encode(signature.to_bytes()))
        .map_err(|e| format!("cannot write {sig_path}: {e}"))?;
    println!("wrote {sig_path}");
    Ok(())
}

fn verify(binary: Option<&String>, public_hex: Option<&String>) -> Result<(), String> {
    let (binary, public_hex) = match (binary, public_hex) {
        (Some(b), Some(p)) => (b, p),
        _ => return Err(usage()),
    };
    on_device::integrity::verify_file(public_hex, Path::new(binary))?;
    println!("{binary}: signature OK");
    Ok(())
}

/// Accept either inline hex or a path to a file containing the hex secret.
fn read_secret(secret_arg: &str) -> Result<[u8; 32], String> {
    let hex_str = match std::fs::read_to_string(secret_arg) {
        Ok(contents) => contents,
        Err(_) => secret_arg.to_string(),
    };
    let bytes = hex::decode(hex_str.trim()).map_err(|e| format!("invalid secret hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("secret must be 32 bytes, got {}", v.len()))
}
