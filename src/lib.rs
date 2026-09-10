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
//!
//! You can either run the binary:
//! ```ignore
//! ---------------------------------------------------
//! Initializing RustHound-CE at 13:37:00 UTC on 01/12/23
//! Powered by @g0h4n_0
//! ---------------------------------------------------
//! 
//! Active Directory data collector for BloodHound Community Edition.
//! g0h4n <https://twitter.com/g0h4n_0>
//! 
//! Usage: rusthound-ce [OPTIONS] --domain <domain>
//! 
//! Options:
//!   -v...          Set the level of verbosity
//!   -h, --help     Print help
//!   -V, --version  Print version
//! 
//! REQUIRED VALUES:
//!   -d, --domain <domain>  Domain name like: DOMAIN.LOCAL
//! 
//! OPTIONAL VALUES:
//!   -u, --ldapusername <ldapusername>  LDAP username, like: user@domain.local
//!   -p, --ldappassword <ldappassword>  LDAP password
//!   -H, --hashes <hashes>              NT hash for pass-the-hash authentication (NTLM), accept [NTHASH, :NTHASH, LMHASH:NTHASH]
//!   -f, --ldapfqdn <ldapfqdn>          Domain Controller FQDN like: DC01.DOMAIN.LOCAL or just DC01
//!   -i, --ldapip <ldapip>              Domain Controller IP address like: 192.168.1.10
//!   -P, --ldapport <ldapport>          LDAP port [default: 389, or 636 with --ldaps]
//!   -n, --name-server <name-server>    Alternative IP address name server to use for DNS queries
//!   -o, --output <output>              Output directory where you would like to save JSON files [default: ./]
//! 
//! CERTIFICATE AUTHENTICATION:
//!       --pfx <pfx>            PFX/PKCS#12 client certificate for certificate authentication (Pass-the-Certificate). Uses StartTLS by default, or LDAPS with --ldaps
//!       --pfx-pass <pfx-pass>  Password protecting the PFX file (optional)
//!       --crt <crt>            PEM client certificate for certificate authentication (use with --key)
//!       --key <key>            PEM private key for certificate authentication (use with --crt)
//! 
//! OPTIONAL FLAGS:
//!   -c, --collectionmethod [<COLLECTIONMETHOD>]
//!           Which information to collect. Supported: All (LDAP, SMB, HTTP), DCOnly (LDAP + SYSVOL, no member-machine connections), Session (user sessions over RPC), RegistryOnly (sessions over WINREG), LdapOnly (LDAP only, no machine or SYSVOL) (default: All) [possible values: All, DCOnly, Session, RegistryOnly, LdapOnly]
//!       --ldap-filter <ldap-filter>
//!           Use custom ldap-filter default is : (objectClass=*)
//!       --ldaps
//!           Force LDAPS using for request like: ldaps://DOMAIN.LOCAL/
//!   -k, --kerberos
//!           Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters for Linux.
//!       --dns-tcp
//!           Use TCP instead of UDP for DNS queries
//!   -z, --zip
//!           Compress the JSON files into a zip archive
//!       --cache
//!           Cache LDAP search results to disk (reduce memory usage on large domains)
//!       --cache-buffer <cache_buffer>
//!           Buffer size to use when caching [default: 1000]
//!       --resume
//!           Resume the collection from the last saved state
//! 
//! OPTIONAL MODULES:
//!       --fqdn-resolver  Use fqdn-resolver module to get computers IP address
//! ```
//! 
//! Or build your own using the ldap_search() function:
//! ```ignore
//! # use rusthound::ldap::ldap_search;
//! # let ldaps = true;
//! # let ip = Some("127.0.0.1");
//! # let port = Some(676);
//! # let domain = "DOMAIN.COM";
//! # let ldapfqdn = "ad1.domain.com";
//! # let username = Some("user");
//! # let password = Some("pwd");
//! # let kerberos= false;
//! let result = ldap_search(
//!     &ldaps,
//!     &Some(ip),
//!     &Some(port),
//!     &domain,
//!     &ldapfqdn,
//!     &username,
//!     &password,
//!     kerberos,
//! );
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