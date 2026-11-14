//! Offline signing helper for `on-device`.
//!
//! ```text
//! sign keygen
//!     Generate a keypair. Prints `secret: <hex>` and `public: <hex>`.
//!     Put `public` in `.env` as `SIGNING_PUBKEY=` and rebuild, then keep
//!     `secret` offline.
//!
//! sign sign <binary> <secret-hex>
//!     Write `<binary>.sig` (hex Ed25519 signature) for the given binary.
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
        Some("keygen") => keygen(),
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
    "usage:\n  sign keygen\n  sign sign <binary> <secret-hex>\n  sign verify <binary> <public-hex>"
        .to_string()
}

fn keygen() -> Result<(), String> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| format!("csprng failure: {e}"))?;
    let signing_key = SigningKey::from_bytes(&seed);
    println!("secret: {}", hex::encode(signing_key.to_bytes()));
    println!("public: {}", hex::encode(signing_key.verifying_key().to_bytes()));
    Ok(())
}

fn sign(binary: Option<&String>, secret_hex: Option<&String>) -> Result<(), String> {
    let (binary, secret_hex) = match (binary, secret_hex) {
        (Some(b), Some(s)) => (b, s),
        _ => return Err(usage()),
    };

    let seed = decode_seed(secret_hex)?;
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

fn decode_seed(secret_hex: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(secret_hex.trim()).map_err(|e| format!("invalid secret hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("secret must be 32 bytes, got {}", v.len()))
}
