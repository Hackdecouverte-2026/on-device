//! on-device
//!
//! Validates the current system proxy against a build-time allowlist, discovers
//! the logged-in user's Microsoft Entra ID, trades it for a proxy credential token via
//! `POST /auth`, then logs into the system proxy with those credentials.
//!
//! Allowed proxy endpoints are bundled at compile time from `.env`
//! (`include_str!`), so changing them requires a rebuild. Protocol strings are
//! obfuscated in the binary with `obfstr`, and the running image is checked
//! against a detached Ed25519 signature (see [`integrity`]).

use std::env;
use std::process::Command;

use obfstr::obfstr;
use on_device::integrity;
use serde_json::Value;
use sysproxy::Sysproxy;

#[derive(Debug, Clone)]
struct ProxyEndpoint {
    /// Full URL from `.env`, e.g. `http://proxy.example.com:8080`.
    base: String,
    host: String,
    port: u16,
}

#[derive(Debug)]
struct EntraIdentity {
    /// Entra (AAD) object ID of the logged-in user.
    id: String,
    /// User principal name, when available (used for logging only).
    upn: Option<String>,
}

// ---------------------------------------------------------------------------
// Compile-time proxy allowlist
// ---------------------------------------------------------------------------

/// Parse the bundled `.env` into the allowed proxy endpoints.
fn parse_allowed_proxies(src: &str) -> Result<Vec<ProxyEndpoint>, String> {
    let mut allowed = Vec::new();
    for (idx, line) in src.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!(".env:{}: expected `KEY=VALUE`, got {:?}", idx + 1, line))?;
        let key = key.trim().to_ascii_uppercase();
        if key != obfstr!("PROXY")
            && key != obfstr!("ALLOWED_PROXY")
            && !key.starts_with(obfstr!("PROXY_"))
        {
            continue;
        }
        let endpoint = parse_endpoint(value.trim())
            .ok_or_else(|| format!(".env:{}: invalid proxy URL {:?}", idx + 1, value.trim()))?;
        allowed.push(endpoint);
    }
    if allowed.is_empty() {
        return Err(".env: no `PROXY=` entries found".into());
    }
    Ok(allowed)
}

/// Read `KEY=VALUE` from `.env`-style text; returns `None` if absent.
fn parse_env_value(src: &str, wanted: &str) -> Option<String> {
    src.lines().find_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let (key, value) = line.split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case(wanted)
            .then(|| value.trim().to_string())
    })
}

fn parse_endpoint(raw: &str) -> Option<ProxyEndpoint> {
    let (scheme, rest) = raw.split_once("://")?;
    if !(scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")) {
        return None;
    }
    let default_port = if scheme.eq_ignore_ascii_case("https") {
        443
    } else {
        80
    };
    let host_port = rest.split(['/', '?', '#']).next()?;
    let (host, port) = match host_port.rsplit_once(':') {
        Some((host, port)) => (host, port.parse().ok()?),
        None => (host_port, default_port),
    };
    if host.is_empty() {
        return None;
    }
    Some(ProxyEndpoint {
        base: raw.to_string(),
        host: host.to_ascii_lowercase(),
        port,
    })
}

/// The current system proxy must be one of the allowed endpoints.
fn match_allowed(current: &Sysproxy, allowed: &[ProxyEndpoint]) -> Option<ProxyEndpoint> {
    allowed
        .iter()
        .find(|ep| ep.host == current.host.to_ascii_lowercase() && ep.port == current.port)
        .cloned()
}

// ---------------------------------------------------------------------------
// Entra ID discovery
// ---------------------------------------------------------------------------

/// Find the Entra ID of the user logged into this device.
///
/// Sources, in order of preference:
/// 1. native Entra join: `dsAttrTypeNative:objectGUID` on the local user record;
/// 2. MSAL account cache (`~/.azure/msal_token_cache.json`) — `home_account_id`,
///    whose first dot-separated segment is the Entra object ID.
fn discover_entra_id() -> Result<EntraIdentity, String> {
    if let Some(identity) = entra_from_dscl() {
        return Ok(identity);
    }
    if let Some(identity) = entra_from_msal() {
        return Ok(identity);
    }
    Err(
        "could not determine the Entra ID of the logged-in user: no \
         dsAttrTypeNative:objectGUID on the local user record and no account in \
         ~/.azure/msal_token_cache.json"
            .into(),
    )
}

fn entra_from_dscl() -> Option<EntraIdentity> {
    let user = env::var("USER").ok()?;
    let target = format!("/Users/{user}");
    let out = Command::new("dscl")
        .args([".", "-read", target.as_str()])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if !key.trim_end().ends_with("objectGUID") {
            continue;
        }
        let guid = value.trim().trim_matches(['{', '}']).to_ascii_lowercase();
        if is_uuid(&guid) {
            return Some(EntraIdentity {
                id: guid,
                upn: None,
            });
        }
    }
    None
}

fn entra_from_msal() -> Option<EntraIdentity> {
    let home = env::var("HOME").ok()?;
    let path = format!("{home}/.azure/msal_token_cache.json");
    let data = std::fs::read_to_string(path).ok()?;
    let root: Value = serde_json::from_str(&data).ok()?;
    let accounts = root.get("Account")?.as_object()?;
    for account in accounts.values() {
        // home_account_id = "<object_id>.<tenant_id>" for Entra accounts.
        let home_id = account.get("home_account_id")?.as_str()?;
        let Some(oid) = home_id.split('.').next() else {
            continue;
        };
        if !is_uuid(oid) {
            continue;
        }
        let upn = account
            .get("username")
            .and_then(Value::as_str)
            .map(String::from);
        return Some(EntraIdentity {
            id: oid.to_ascii_lowercase(),
            upn,
        });
    }
    None
}

fn is_uuid(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() == 36
        && bytes[8] == b'-'
        && bytes[13] == b'-'
        && bytes[18] == b'-'
        && bytes[23] == b'-'
        && bytes
            .iter()
            .all(|&b| !(b != b'-' && !b.is_ascii_hexdigit()))
}

// ---------------------------------------------------------------------------
// /auth: trade the Entra ID for a proxy credential token
// ---------------------------------------------------------------------------

/// POST `{entra_id}` to `<proxy>/auth`; the response carries a token.
///
/// Contract (client side — see README):
///   POST /auth
///   Content-Type: application/json
///   {"entra_id": "<entra object id>"}
///
///   HTTP 200
///   {"token": "<proxy credential token>"}
async fn fetch_proxy_token(
    endpoint: &ProxyEndpoint,
    identity: &EntraIdentity,
) -> Result<String, String> {
    // Never route /auth through a system proxy: it is served by the proxy itself,
    // and the system proxy may not be authenticated yet.
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;
    let url = format!(
        "{}{}",
        endpoint.base.trim_end_matches('/'),
        obfstr!("/auth")
    );
    let mut body = serde_json::Map::new();
    body.insert(
        obfstr!("entra_id").to_string(),
        Value::String(identity.id.clone()),
    );
    let body = Value::Object(body);

    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("POST {url} failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("POST {url} returned HTTP {}", resp.status()));
    }
    let parsed: Value = resp
        .json()
        .await
        .map_err(|e| format!("POST {url}: invalid JSON response: {e}"))?;
    let token = parsed
        .get(obfstr!("token"))
        .and_then(Value::as_str)
        .ok_or_else(|| format!("POST {url}: response has no `token` string field"))?
        .to_string();
    if token.is_empty() {
        return Err(format!("POST {url}: empty token"));
    }
    Ok(token)
}

// ---------------------------------------------------------------------------
// Proxy login (macOS: authenticated system proxy via networksetup)
// ---------------------------------------------------------------------------

/// Log into the system proxy with `(username, credential)`.
///
/// `sysproxy` has no credential support, so on macOS we drive
/// `networksetup -setwebproxy/-setsecurewebproxy ... on <user> <pass>`.
/// Requires admin privileges.
fn login_proxy(endpoint: &ProxyEndpoint, username: &str, credential: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let service = default_network_service()?;
        let port = endpoint.port.to_string();
        for (setter, state_setter) in [
            ("-setwebproxy", "-setwebproxystate"),
            ("-setsecurewebproxy", "-setsecurewebproxystate"),
        ] {
            let args: Vec<String> = vec![
                setter.to_string(),
                service.clone(),
                endpoint.host.clone(),
                port.clone(),
                "on".to_string(),
                username.to_string(),
                credential.to_string(),
            ];
            run_networksetup(&args)?;
            run_networksetup(&[state_setter.to_string(), service.clone(), "on".to_string()])?;
        }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (endpoint, username, credential);
        Err("authenticated proxy login is only implemented on macOS (networksetup)".into())
    }
}

#[cfg(target_os = "macos")]
fn default_network_service() -> Result<String, String> {
    let out = Command::new("networksetup")
        .arg("-listallnetworkservices")
        .output()
        .map_err(|e| format!("failed to list network services: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "networksetup -listallnetworkservices failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut lines = text.lines();
    lines.next(); // header: "An asterisk (*) denotes..." (may be absent on some setups)
    for line in lines {
        let line = line.trim();
        if !line.is_empty() && !line.starts_with('*') {
            return Ok(line.to_string());
        }
    }
    Err("no enabled network service found".into())
}

#[cfg(target_os = "macos")]
fn run_networksetup(args: &[String]) -> Result<(), String> {
    let out = Command::new("networksetup")
        .args(args)
        .output()
        .map_err(|e| format!("failed to run networksetup: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(format!("networksetup {} failed: {}", args[0], stderr));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    // Compile-time bundled `.env`, obfuscated in the binary (`obfstr`).
    obfstr! {
        let env_src = include_str!("../.env");
    }

    // 0. Verify this binary's own detached signature before doing anything else.
    let signing_pubkey = parse_env_value(env_src, obfstr!("SIGNING_PUBKEY")).unwrap_or_default();
    integrity::enforce(&signing_pubkey)?;

    // 1. Validate the current system proxy against the compile-time allowlist.
    let allowed = parse_allowed_proxies(env_src)?;
    let current = Sysproxy::get_system_proxy()
        .map_err(|e| format!("failed to read the current system proxy: {e}"))?;
    if !current.enable {
        return Err(
            "no system proxy is configured on this device; expected one of the allowed values:"
                .to_string(),
        );
    }
    let allowed_list = allowed
        .iter()
        .map(|ep| ep.base.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let endpoint = match_allowed(&current, &allowed).ok_or_else(|| {
        format!(
            "current system proxy ({}:{}) is not an allowed value; allowed endpoints (bundled from .env):\n{}",
            current.host, current.port, allowed_list,
        )
    })?;
    println!("proxy validated: {}", endpoint.base);

    // 2. Discover the Entra ID of the logged-in user.
    let identity = discover_entra_id()?;
    match &identity.upn {
        Some(upn) => println!("entra id: {} ({upn})", identity.id),
        None => println!("entra id: {}", identity.id),
    }

    // 3. Trade it for a proxy credential token.
    let token = fetch_proxy_token(&endpoint, &identity).await?;
    println!("proxy token obtained from {}/auth", endpoint.base);

    // 4. Log into the proxy with that token.
    login_proxy(&endpoint, &identity.id, &token)?;
    println!("logged into system proxy: {}", endpoint.base);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_allowed_proxies_and_skips_comments() {
        let src = "# comment\nPROXY=http://a.example.com:8080\n\nPROXY_ALT=https://b.example.com:3128\nOTHER=x\n";
        let allowed = parse_allowed_proxies(src).unwrap();
        assert_eq!(allowed.len(), 2);
        assert_eq!(allowed[0].host, "a.example.com");
        assert_eq!(allowed[0].port, 8080);
        assert_eq!(allowed[1].port, 3128);
    }

    #[test]
    fn rejects_empty_allowlist() {
        assert!(parse_allowed_proxies("# nothing\n").is_err());
    }

    #[test]
    fn defaults_port_by_scheme() {
        assert_eq!(parse_endpoint("http://proxy.example.com").unwrap().port, 80);
        assert_eq!(
            parse_endpoint("https://proxy.example.com").unwrap().port,
            443
        );
    }

    #[test]
    fn match_allowed_is_case_insensitive_on_host() {
        let allowed = parse_allowed_proxies("PROXY=http://Proxy.Example.com:8080\n").unwrap();
        let current = Sysproxy {
            enable: true,
            host: "proxy.example.com".into(),
            port: 8080,
            bypass: String::new(),
        };
        assert!(match_allowed(&current, &allowed).is_some());
        let other = Sysproxy {
            port: 9999,
            ..current
        };
        assert!(match_allowed(&other, &allowed).is_none());
    }

    #[test]
    fn msal_discovery_smoke() {
        let home = match env::var("HOME") {
            Ok(h) => h,
            Err(_) => return,
        };
        if !std::path::Path::new(&format!("{home}/.azure/msal_token_cache.json")).exists() {
            return; // no MSAL cache on this machine; nothing to check
        }
        let id = entra_from_msal().expect("MSAL cache present but no Entra account parsed");
        assert!(is_uuid(&id.id), "discovered id is not a UUID: {}", id.id);
        eprintln!("discovered entra id {} ({:?})", id.id, id.upn);
    }

    #[test]
    fn uuid_validation() {
        assert!(is_uuid("c69fc9bd-a1b8-4ac5-b4b0-0be024e97c52"));
        assert!(!is_uuid("not-a-uuid"));
        assert!(!is_uuid("c69fc9bd-a1b8-4ac5-b4b0-0be024e97c5"));
    }
}
