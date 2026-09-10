# Using RustHound-CE as a Rust library

RustHound-CE is both a binary and a library. You can embed its Active Directory
collection pipeline in your own Rust program with two composable functions:

```rust
let mut ldap = rusthound_ce::ldap_auth(&options).await?;   // 1. authenticate
let out      = rusthound_ce::run_collection(&mut ldap, &options).await?; // 2. collect + parse + modules + JSON/zip
```

`ldap_auth` connects and authenticates (simple bind, pass-the-hash, Kerberos, or
certificate) and hands back a ready `ldap3::Ldap` session. `run_collection` runs
the whole workflow over that session and returns the output path. Neither calls
`process::exit`; failures are returned as `Err`, and the session is yours to
reuse or close.

- [Add the dependency](#add-the-dependency)
- [Quick start](#quick-start)
- [Bring your own LDAP session](#bring-your-own-ldap-session)
- [The Options struct](#the-options-struct)
- [Storage modes](#storage-modes)
- [Feature flags](#feature-flags)
- [API reference](#api-reference)

## Add the dependency

Directly inside your `Cargo.toml` file:

```toml
[dependencies]
rusthound-ce = "2.5.13"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
log = "0.4"
```

On Linux the default build needs the Kerberos/GSSAPI system libraries
(`clang`, `libclang-dev`, `libkrb5-dev`). To build without Kerberos, use the
`nogssapi` feature, see [Feature flags](#feature-flags).

## Quick start

Collect `essos.local` from [GOAD](https://github.com/Orange-Cyberdefense/GOAD) lab with username/password over LDAPS, in memory, zipped:

```rust
use rusthound_ce::{ldap_auth, run_collection, args::{Options, CollectionMethod}};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    // 1) Prepare RustHound-CE options
    let options = Options {
        domain: "essos.local".to_string(),
        username: Some("daenerys.targaryen@essos.local".to_string()),
        password: Some("BurnThemAll!".to_string()),
        ldapfqdn: Some("meereen.essos.local".to_string()),
        ip: None,
        port: None,                             // default follows the scheme (636 for LDAPS)
        name_server: "not set".to_string(),
        path: ".".to_string(),          // output directory
        collection_method: CollectionMethod::All,
        ldaps: true,
        dns_tcp: false,
        fqdn_resolver: false,
        hashes: None,
        kerberos: false,
        pfx: None,
        pfx_pass: None,
        crt: None,
        key: None,
        zip: true,
        verbose: log::LevelFilter::Info,
        ldap_filter: "(objectClass=*)".to_string(),
        cache: false,                           // in memory
        cache_buffer_size: 1000,
        resume: false,
    };

    // 2) Perform ldap auth
    let mut ldap = ldap_auth(&options).await?;
    // 3) Collect and save output inside ZIP in current directory
    let out = run_collection(&mut ldap, &options).await?;
    println!("Output written to {out}");

    Ok(())
}
```

Swap the auth fields for other modes: set `hashes` for pass-the-hash,
`kerberos: true` for a ticket from `KRB5CCNAME`, or `crt`/`key` (or `pfx`) for
certificate authentication.

## Bring your own LDAP session

You are not required to use `ldap_auth`. If you already have an authenticated
`ldap3::Ldap` handle, for example one you bound with a client certificate in
your own tool, pass it straight to `run_collection`:

```rust
// `ldap` is your own already-authenticated ldap3::Ldap session.
async fn collect(ldap: &mut ldap3::Ldap) -> Result<(), Box<dyn std::error::Error>> {

    let options = Options {
        domain: "essos.local".to_string(),
        username: None,
        password: None,
        ldapfqdn: Some("meereen.essos.local".to_string()),
        ip: None,
        port: None,                             // default follows the scheme (636 for LDAPS)
        name_server: "not set".to_string(),
        path: ".".to_string(),          // output directory
        collection_method: CollectionMethod::LdapOnly,    // Certificate auth has no SMB credentials, so skip SMB-based modules:
        ldaps: true,
        dns_tcp: false,
        fqdn_resolver: false,
        hashes: None,
        kerberos: false,
        pfx: None,
        pfx_pass: None,
        crt: None,
        key: None,
        zip: true,
        verbose: log::LevelFilter::Info,
        ldap_filter: "(objectClass=*)".to_string(),
        cache: false,                           // in memory
        cache_buffer_size: 1000,
        resume: false,
    };

    let out = run_collection(ldap, &options).await?;
    println!("Output written to {out}");

    Ok(())
}
```

## The Options struct

`Options` mirrors the CLI flags. The fields you will usually set:

| Field | Meaning |
|---|---|
| `domain` | target domain, e.g. `essos.local` |
| `username` / `password` | simple bind credentials |
| `hashes` | NT hash for pass-the-hash (`NTHASH`, `:NTHASH`, or `LMHASH:NTHASH`) |
| `kerberos` | use a Kerberos ticket from `KRB5CCNAME` |
| `pfx` / `pfx_pass` / `crt` / `key` | certificate authentication |
| `ldapfqdn` / `ip` / `port` | how to reach the DC |
| `ldaps` | force LDAPS (636) |
| `collection_method` | `All`, `DCOnly`, `Session`, `RegistryOnly`, `LdapOnly` |
| `path` | output directory for the JSON/zip |
| `zip` | also write a `.zip` |
| `ldap_filter` | custom LDAP filter (default `(objectClass=*)`) |
| `cache` / `cache_buffer_size` / `resume` | disk cache and resume |

Fields you don't use should be `None` / `false` / their default.

## Storage modes

Selected by fields on `Options`:

- **In memory** (default): `cache = false`, `resume = false`.
- **Disk cache**: `cache = true`, entries stream to
  `.rusthound-cache/<domain>/ldap.bin` (buffer = `cache_buffer_size`).
- **Resume**: `resume = true`, skip collection, parse an existing cache.

## Feature flags

- **default**: `ldap3/tls-rustls-ring` + `ldap3/gssapi` + `ldap3/ntlm` (Kerberos
  included; needs system Kerberos libs on Linux).
- **nogssapi**: `ldap3/tls-rustls-ring` + `ldap3/ntlm` (no Kerberos, no system
  Kerberos libs; good for musl / cross-compilation / macOS).

```toml
rusthound-ce = { version = "2.5.13", default-features = false, features = ["nogssapi"] }
```

Certificate, username/password and pass-the-hash work under both; only Kerberos
needs the default (gssapi) feature.

## API reference

```rust
// Authenticate from `options`, returning a ready session.
pub async fn ldap_auth(
    options: &args::Options,
) -> Result<ldap3::Ldap, Box<dyn std::error::Error>>;

// Full workflow over an authenticated session: collect -> modules -> JSON/zip.
pub async fn run_collection(
    ldap: &mut ldap3::Ldap,
    options: &args::Options,
) -> Result<String, Box<dyn std::error::Error>>;
```