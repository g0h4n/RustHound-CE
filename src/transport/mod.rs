//! Network transports used by RustHound-CE to talk to Active Directory.
//!
//! * `ldap`: LDAP/LDAPS connection, authentication (NTLM, pass the hash,
//!   Kerberos) and paged search used for the main collection phase.
//! * `adws`: ADWS/SOAP transport (TCP 9389) via the `adws-rs` crate, an
//!   alternative to LDAP for the directory collection (`--transport soap`).
//! * `smb`: SMB and MS RPC transport. IPC$ pipes (SRVSVC, WKSSVC, WINREG) for
//!   the sessions module, and the SYSVOL share for GPO file collection.
//! * `gss`: minimal SPNEGO framing for a Kerberos AP-REQ carried in an SMB2
//!   SESSION_SETUP.
//! * `kerberos`: pass the ticket helper. Loads a TGT from a ccache, requests a
//!   cifs/<host> service ticket and builds the AP-REQ for SMB Kerberos auth.
//! * `cert`: rustls client config carrying a client certificate (PFX/PEM) for
//!   certificate authentication over LDAPS.
//!
//! The [`DirectoryTransport`] trait abstracts the directory read so the main
//! collection can run over either `ldap` or `adws`, selected at runtime by
//! `--transport ldap|soap`.

use async_trait::async_trait;
use log::trace;
use std::error::Error;

use crate::args::{Options, Transport};
use crate::storage::Storage;
use crate::transport::ldap::LdapSearchEntry;

pub mod ldap;
pub mod adws;
pub mod smb;
pub mod gss;
pub mod kerberos;
pub mod cert;

/// Abstracts the directory read so the collection can run over LDAP or ADWS/SOAP.
///
/// Object-safe on purpose: the per-entry `sink` closure keeps the trait generic
/// over the storage backend (disk cache or in-memory), so it can be used as a
/// `&mut dyn DirectoryTransport`.
#[async_trait]
pub trait DirectoryTransport: Send {
    /// Naming contexts to walk (Schema / Domain / Configuration …), ordered as
    /// the collectors expect.
    async fn naming_contexts(&mut self) -> Result<Vec<String>, Box<dyn Error>>;

    /// Stream every object under `cn` matching `filter` into `sink`, requesting
    /// the SD-flags control so `nTSecurityDescriptor` is returned. Returns the
    /// number of entries pushed.
    async fn collect_context(
        &mut self,
        cn: &str,
        filter: &str,
        sink: &mut (dyn FnMut(LdapSearchEntry) -> Result<(), Box<dyn Error>> + Send),
    ) -> Result<usize, Box<dyn Error>>;
}

/// Authenticate and return a ready transport, chosen by `options.transport`:
/// LDAP/LDAPS (default) or ADWS/SOAP (`--transport soap`).
pub async fn connect(options: &Options) -> Result<Box<dyn DirectoryTransport>, Box<dyn Error>> {
    match options.transport {
        Transport::Soap => {
            Ok(Box::new(adws::adws_auth(options).await?))
        }
        Transport::Ldap => {
            Ok(Box::new(ldap::LdapTransport(ldap::ldap_auth(options).await?)))
        }
    }
}

/// Collect every namingContext into `storage` over any [`DirectoryTransport`],
/// returning the total object count. Transport-agnostic replacement for the old
/// `ldap::collect_from_ldap_into`; the per-context walk lives in each transport.
pub(crate) async fn collect_into<S>(
    transport: &mut dyn DirectoryTransport,
    ldapfilter: &str,
    storage: &mut S,
) -> Result<usize, Box<dyn Error>> where S: Storage<LdapSearchEntry> + Send,
{
    let ncs = transport.naming_contexts().await?;
    trace!("naming_contexts: {:?}", &ncs);

    if !ncs.iter().any(|s| s.contains("Configuration")) {
        return Err("no Configuration namingContext found (is the target a Domain Controller?)".into());
    }

    let mut total = 0usize;
    for cn in &ncs {
        // Recreated each iteration so the mutable borrow of `storage` is released
        // between contexts. `+ Send` on the sink holds because `S: Send`.
        let mut sink = |e: LdapSearchEntry| -> Result<(), Box<dyn Error>> {
            storage.add(e)?;
            Ok(())
        };
        total += transport.collect_context(cn, ldapfilter, &mut sink).await?;
    }

    storage.flush()?;
    Ok(total)
}

/// Render `host:port` for a socket connect, preferring `resolved` over `host`.
///
/// `host` may be an IPv6 literal, which is bracketed; `resolved` is the IP the
/// host resolved to, if any (see [`resolved_host_port`]).
pub(crate) fn host_port(host: &str, port: u16, resolved: Option<&str>) -> String {
    match resolved {
        Some(ip) if ip.contains(':') => format!("[{ip}]:{port}"),
        Some(ip) => format!("{ip}:{port}"),
        None if host.contains(':') => format!("[{host}]:{port}"),
        None => format!("{host}:{port}"),
    }
}

/// `host:port` with the host resolved to an IP literal through trust-dns.
///
/// Every Rust standard-library connect helper resolves names with
/// `getaddrinfo`, i.e. NSS, which is fatal in a statically linked glibc binary
/// as soon as a module has to be `dlopen`ed (see
/// [`ldap::resolve_url_host`]). IP literals are passed through untouched and a
/// failed lookup falls back to `host`, so behaviour is unchanged wherever NSS
/// was working.
pub(crate) async fn resolved_host_port(host: &str, port: u16) -> String {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return host_port(host, port, None);
    }
    let ip = crate::modules::resolver::resolv::resolve_hostname(host).await;
    if let Some(ref ip) = ip {
        log::debug!("[{host}] resolved to {ip} for TCP connect");
    }
    host_port(host, port, ip.as_deref())
}

/// Blocking [`resolved_host_port`], for callers already on a blocking thread.
pub(crate) fn resolved_host_port_blocking(host: &str, port: u16) -> String {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return host_port(host, port, None);
    }
    let ip = trust_dns_resolver::Resolver::from_system_conf()
        .ok()
        .and_then(|resolver| resolver.lookup_ip(host).ok())
        .and_then(|response| {
            let mut fallback = None;
            for address in response.iter() {
                if address.is_ipv4() {
                    return Some(address.to_string());
                }
                fallback.get_or_insert(address);
            }
            fallback.map(|address| address.to_string())
        });
    if let Some(ref ip) = ip {
        log::debug!("[{host}] resolved to {ip} for TCP connect");
    }
    host_port(host, port, ip.as_deref())
}
/// `reqwest` DNS resolver backed by trust-dns.
///
/// `reqwest`'s default resolver calls `getaddrinfo` (NSS) on a blocking thread,
/// which is the same static-glibc SIGFPE path as the plain TCP connects above.
/// Installed with `ClientBuilder::dns_resolver`, it also covers redirects; the
/// URL keeps its host name, so the `Host` header and TLS SNI are unchanged.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TrustDnsResolver;

impl reqwest::dns::Resolve for TrustDnsResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let resolver = trust_dns_resolver::TokioAsyncResolver::tokio_from_system_conf()?;
            let lookup = resolver.lookup_ip(host.as_str()).await?;
            let addrs: Vec<std::net::SocketAddr> = lookup
                .iter()
                .map(|ip| std::net::SocketAddr::new(ip, 0))
                .collect();
            log::debug!("[{host}] resolved to {addrs:?} for HTTP");
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{host_port, TrustDnsResolver};

    #[test]
    fn host_port_uses_the_resolved_ip_over_the_name() {
        assert_eq!(host_port("dc01.corp.local", 445, Some("10.0.0.5")), "10.0.0.5:445");
    }

    #[test]
    fn host_port_keeps_ip_literals_as_they_are() {
        assert_eq!(host_port("10.0.0.5", 445, None), "10.0.0.5:445");
        assert_eq!(host_port("::1", 88, None), "[::1]:88");
    }

    #[test]
    fn host_port_falls_back_to_the_name_when_resolution_failed() {
        assert_eq!(host_port("dc01", 445, None), "dc01:445");
    }

    #[test]
    fn host_port_brackets_a_resolved_ipv6_literal() {
        assert_eq!(host_port("dc01", 88, Some("::1")), "[::1]:88");
    }

    #[tokio::test]
    async fn trust_dns_resolver_answers_localhost_from_the_hosts_file() {
        use reqwest::dns::Resolve;
        let name: reqwest::dns::Name = "localhost".parse().unwrap();
        let addrs: Vec<_> = TrustDnsResolver.resolve(name).await.unwrap().collect();
        assert!(!addrs.is_empty());
        assert!(addrs.iter().all(|a| a.ip().is_loopback()), "{addrs:?}");
    }
}
