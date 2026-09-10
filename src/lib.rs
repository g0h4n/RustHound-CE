//! <p align="center">
//!     <picture>
//!         <source media="(prefers-color-scheme: dark)" srcset="https://github.com/g0h4n/RustHound-CE/raw/main/img/rusthoundce-transparent-dark-theme.png">
//!         <source media="(prefers-color-scheme: light)" srcset="https://github.com/g0h4n/RustHound-CE/raw/main/img/rusthoundce-transparent-light-theme.png">
//!         <img src="https://github.com/g0h4n/RustHound-CE/raw/main/img/rusthoundce-transparent-dark-theme.png" alt="rusthound-ce logo" width='250' />
//!     </picture>
//! </p>
//! <hr />
//!
//! RustHound-CE is a cross-platform and cross-compiled BloodHound collector tool written in Rust, making it compatible with Linux, Windows, and macOS. It therefore generates all the JSON files that can be analyzed by BloodHound Community Edition. This version is only compatible with [BloodHound Community Edition](https://github.com/SpecterOps/BloodHound). The version compatible with [BloodHound Legacy](https://github.com/BloodHoundAD/BloodHound) can be found on [NeverHack's github](https://github.com/NH-RED-TEAM/RustHound).
//!
//! RustHound-CE can be use as a library. The pipeline is exposed as two composable
//! functions, see [INTEGRATION.md](https://github.com/g0h4n/RustHound-CE/blob/main/INTEGRATION.md)
//! for the full guide.
//!
//! Authenticate, then run the whole collection:
//! ```ignore
//! use rusthound_ce::{ldap_auth, run_collection, args::{Options, CollectionMethod}};
//!
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! let options = Options {
//!     domain: "essos.local".to_string(),
//!     username: Some("daenerys.targaryen@essos.local".to_string()),
//!     password: Some("BurnThemAll!".to_string()),
//!     ldapfqdn: Some("meereen.essos.local".to_string()),
//!     ldaps: true,
//!     path: "/tmp/demo".to_string(),
//!     collection_method: CollectionMethod::All,
//!     zip: true,
//!     ..Default::default()
//! };
//!
//! // 1. authenticate (simple bind, pass-the-hash, Kerberos, or certificate)
//! let mut ldap = ldap_auth(&options).await?;
//! // 2. collect -> parse -> modules -> JSON/zip, returns the output path
//! let out = run_collection(&mut ldap, &options).await?;
//! println!("Output written to {out}");
//! # Ok(())
//! # }
//! ```
//!
//! Or bring your own already-authenticated `ldap3::Ldap` session (for example
//! one bound with a client certificate) and skip `ldap_auth`:
//! ```ignore
//! use rusthound_ce::{run_collection, args::{Options, CollectionMethod}};
//!
//! # async fn demo(ldap: &mut ldap3::Ldap, mut options: Options) -> Result<(), Box<dyn std::error::Error>> {
//! options.collection_method = CollectionMethod::LdapOnly; // no SMB creds over cert auth
//! let out = run_collection(ldap, &options).await?;
//! println!("Output written to {out}");
//! # Ok(())
//! # }
//! ```
//! 
pub mod args;
pub mod banner;
pub mod transport;
pub mod utils;
pub mod api;
pub mod modules;

pub mod enums;
pub mod json;
pub mod objects;
pub (crate) mod storage;


extern crate bitflags;
extern crate chrono;
extern crate regex;

// Reimport key functions and structure
#[doc(inline)]
pub use transport::ldap::ldap_auth;
#[doc(inline)]
pub use ldap3::SearchEntry;

pub use json::maker::make_result;
pub use api::{prepare_results_from_source, prepare_results_from_disk};
pub use storage::{Storage, EntrySource, DiskStorage, DiskStorageReader};