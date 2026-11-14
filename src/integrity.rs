//! Self-signature validation.
//!
//! At startup the binary hashes its own executable image and verifies a detached
//! Ed25519 signature (`<binary>.sig`, hex-encoded) against a public key bundled
//! at compile time (`SIGNING_PUBKEY` in `.env`). Any modification to the binary
//! invalidates the signature and the program refuses to run.
//!
//! The signature is detached because a signature embedded in the file would
//! change the very bytes it signs. Use the `sign` helper binary to generate a
//! keypair and to (re-)sign a build.

use std::path::Path;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Suffix of the detached signature file that sits next to the executable.
pub const SIGNATURE_SUFFIX: &str = ".sig";

/// Verify `data` against a hex-encoded Ed25519 `signature`, using the hex-encoded
/// 32-byte `public_key`.
pub fn verify_bytes(public_key_hex: &str, data: &[u8], signature_hex: &str) -> Result<(), String> {
    let public_key = decode_fixed::<32>(public_key_hex.trim(), "public key")?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|e| format!("invalid public key: {e}"))?;

    let signature_bytes = decode_fixed::<64>(signature_hex.trim(), "signature")?;
    let signature = Signature::from_bytes(&signature_bytes);

    verifying_key
        .verify(data, &signature)
        .map_err(|_| "signature verification failed (binary tampered or wrong key)".to_string())
}

/// Verify a binary against its detached `<binary>.sig` file.
pub fn verify_file(public_key_hex: &str, binary: &Path) -> Result<(), String> {
    let data =
        std::fs::read(binary).map_err(|e| format!("cannot read {}: {e}", binary.display()))?;
    let sig_path = format!("{}{}", binary.display(), SIGNATURE_SUFFIX);
    let signature_hex = std::fs::read_to_string(&sig_path).map_err(|_| {
        format!(
            "missing detached signature {}; sign the build with the `sign` helper",
            sig_path
        )
    })?;
    verify_bytes(public_key_hex, &data, &signature_hex)
}

/// Verify the running executable against its detached signature.
///
/// An empty `public_key_hex` disables the check with a warning; this is intended
/// for development only. Production builds must set `SIGNING_PUBKEY`.
pub fn enforce(public_key_hex: &str) -> Result<(), String> {
    if public_key_hex.trim().is_empty() {
        eprintln!(
            "warning: SIGNING_PUBKEY is not set; skipping self-signature validation \
             (set it in .env and rebuild for a protected build)"
        );
        return Ok(());
    }

    let exe = std::env::current_exe()
        .map_err(|e| format!("cannot locate own executable for signature check: {e}"))?;
    verify_file(public_key_hex, &exe)
}

fn decode_fixed<const N: usize>(hex_str: &str, what: &str) -> Result<[u8; N], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid {what} hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("{what} must be {N} bytes, got {}", v.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn keypair() -> (SigningKey, String) {
        // Deterministic seed keeps tests reproducible.
        let seed = [7u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let public_hex = hex::encode(signing_key.verifying_key().to_bytes());
        (signing_key, public_hex)
    }

    #[test]
    fn accepts_valid_signature() {
        let (signing_key, public_hex) = keypair();
        let data = b"the quick brown fox";
        let signature_hex = hex::encode(signing_key.sign(data).to_bytes());
        assert!(verify_bytes(&public_hex, data, &signature_hex).is_ok());
    }

    #[test]
    fn rejects_tampered_data() {
        let (signing_key, public_hex) = keypair();
        let signature_hex = hex::encode(signing_key.sign(b"original").to_bytes());
        assert!(verify_bytes(&public_hex, b"tampered", &signature_hex).is_err());
    }

    #[test]
    fn rejects_wrong_key() {
        let (signing_key, _) = keypair();
        let data = b"payload";
        let signature_hex = hex::encode(signing_key.sign(data).to_bytes());
        let other_public = hex::encode(
            SigningKey::from_bytes(&[9u8; 32])
                .verifying_key()
                .to_bytes(),
        );
        assert!(verify_bytes(&other_public, data, &signature_hex).is_err());
    }

    #[test]
    fn rejects_malformed_inputs() {
        let (signing_key, public_hex) = keypair();
        let signature_hex = hex::encode(signing_key.sign(b"x").to_bytes());
        assert!(verify_bytes("not-hex", b"x", &signature_hex).is_err());
        assert!(verify_bytes(&public_hex, b"x", "00").is_err());
    }

    #[test]
    fn empty_key_skips_enforcement() {
        assert!(enforce("").is_ok());
    }

    #[test]
    fn end_to_end_sign_and_verify_file() {
        let (signing_key, public_hex) = keypair();
        let path = std::env::temp_dir().join(format!("on-device-test-{}", std::process::id()));
        std::fs::write(&path, b"signed payload").unwrap();
        let signature_hex = hex::encode(signing_key.sign(b"signed payload").to_bytes());
        std::fs::write(format!("{}.sig", path.display()), signature_hex).unwrap();

        assert!(verify_file(&public_hex, &path).is_ok());

        // Tamper with the payload: verification must now fail.
        std::fs::write(&path, b"tampered payload").unwrap();
        assert!(verify_file(&public_hex, &path).is_err());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}.sig", path.display()));
    }
}
