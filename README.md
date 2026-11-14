# on-device

Device-side agent for the Hackdecouverte 2026 proxy project.

## What it does

1. **Validates the current system proxy.** The proxy reachable on this device must be
   one of the endpoints listed in `.env`. The `.env` file is **bundled into the binary
   at compile time** (`include_str!`), so changing the allowlist requires a rebuild.

   ```sh
   cp .env.example .env   # then edit .env to list the real proxy endpoints
   cargo build
   ```

2. **Discovers the logged-in user's Entra ID.** Tries, in order:
   - the local user record (`dscl` `dsAttrTypeNative:objectGUID`, present on Entra-joined Macs);
   - the MSAL account cache (`~/.azure/msal_token_cache.json`), whose
     `home_account_id` is `<entra object id>.<tenant id>`.

3. **Trades the Entra ID for a proxy credential token** via the `/auth` endpoint on
   the proxy.

4. **Logs into the system proxy** with the token (macOS: authenticated proxy via
   `networksetup`; requires admin privileges).

## `/auth` contract

The client sends the Entra object ID of the logged-in user:

```
POST /auth
Content-Type: application/json

{"entra_id": "c69fc9bd-a1b8-4ac5-b4b0-0be024e97c52"}
```

The server responds with a proxy credential token:

```
HTTP 200
Content-Type: application/json

{"token": "<proxy credential token>"}
```

The client then configures the system proxy with `username = <entra_id>` and that
token.

## Hardening: obfuscation and self-signature validation

### Obfuscation

- The whole bundled `.env` and the protocol strings (`/auth`, JSON keys, env keys)
  are obfuscated in the binary at compile time with [`obfstr`](https://crates.io/crates/obfstr).
- `[profile.release]` strips symbols, enables LTO with a single codegen unit, and
  aborts on panic.

```sh
cargo build --release
strings -a target/release/on-device | grep -E '/auth|entra_id|SIGNING_PUBKEY'
```

### Self-signature validation

On startup the agent reads its own executable, and verifies a detached Ed25519
signature (`<binary>.sig`, hex) against the public key compiled into `.env`
(`SIGNING_PUBKEY`). A modified binary fails the check and the agent exits.

The signature is detached because a signature embedded in the file would change
the bytes it signs.

```sh
# 1. Generate a keypair (keep `secret` offline).
cargo run --release --bin sign -- keygen

# 2. Put the printed `public` value in .env as SIGNING_PUBKEY= and rebuild.
cargo build --release

# 3. Sign the built binary (writes target/release/on-device.sig).
cargo run --release --bin sign -- sign target/release/on-device <secret-hex>

# 4. Verify (also usable in CI, no secret required).
cargo run --release --bin sign -- verify target/release/on-device <public-hex>
```

If `SIGNING_PUBKEY` is empty the check is skipped with a warning. This is for
development only; **production builds must set it** (enforced by fail-closed
behavior whenever it is present).
