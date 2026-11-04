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
use log::{info, trace};
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
            info!("Transport: ADWS (SOAP, tcp/9389)");
            Ok(Box::new(adws::adws_auth(options).await?))
        }
        Transport::Ldap => {
            info!("Transport: LDAP");
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