//! ADWS / SOAP transport (TCP 9389), backed by the `adws-rs` crate.
//!
//! An alternative to [`crate::transport::ldap`] for the directory collection,
//! selected with `--transport soap`. It implements the same
//! [`DirectoryTransport`] trait, so the collection pipeline is unchanged: every
//! object is yielded as an `LdapSearchEntry` (`{ dn, attrs, bin_attrs }`).
//!
//! Authentication currently supports password and NT-hash (NTLM); Kerberos and
//! certificate auth over ADWS (PKINIT) are not wired yet.

use crate::args::Options;
use crate::transport::ldap::LdapSearchEntry;
use crate::transport::DirectoryTransport;
use crate::utils::format::parse_hash;

use adws_rs::client::Target;
use adws_rs::{AdwsClient, Credentials, Scope, SdFlags};
use async_trait::async_trait;
use colored::Colorize;
use log::{debug, error, info, warn};
use std::error::Error;

/// Attributes requested per object, mirroring the LDAP collector: all default
/// attributes (`*`), the security descriptor (returned via the SD-flags
/// control), and the computed UAC.
const ADWS_ATTRS: &[&str] = &["*", "nTSecurityDescriptor", "msDS-User-Account-Control-Computed"];

/// AD's default `MaxValRange`: a search returns at most this many values of a
/// multivalued attribute (e.g. `member`). Over LDAP the client completes the
/// rest with ranged retrieval (`member;range=lo-hi`); ADWS does not support
/// that option, so a group at or above this count is completed with the
/// MS-ADCAP `GetADGroupMember` custom action instead.
const MAX_VAL_RANGE: usize = 1500;

/// ADWS implementation of [`DirectoryTransport`]. Wraps a connected
/// `adws_rs::AdwsClient`.
pub struct AdwsTransport {
    client: AdwsClient,
}

/// Connect to the DC's ADWS endpoint (TCP 9389) and authenticate, returning a
/// ready transport. Analogue of `transport::ldap::ldap_auth`.
///
/// The target host is the DC FQDN (`ldapfqdn`), else the IP (`ip`), else the
/// domain. Credentials come from `options`: NT-hash (`hashes`) or password.
pub async fn adws_auth(options: &Options) -> Result<AdwsTransport, Box<dyn Error>> {
    if options.kerberos || options.pfx.is_some() || options.crt.is_some() {
        return Err("--transport soap currently supports only password / NT-hash (NTLM); \
                    Kerberos and certificate auth over ADWS are not wired yet"
            .into());
    }

    let host = options
        .ldapfqdn
        .clone()
        .filter(|s| !s.is_empty())
        .or_else(|| options.ip.clone())
        .unwrap_or_else(|| options.domain.clone());

    let raw_user = options
        .username
        .clone()
        .ok_or("ADWS requires a username (-u)")?;
    // adws-rs rebuilds the NTLM logon name itself as `DOMAIN\sAMAccountName`
    // (auth.rs::logon_name), so hand it the bare sAMAccountName: strip any UPN
    // suffix (`user@domain`) or down-level prefix (`DOMAIN\user`).
    let username = bare_sam(&raw_user);
    // Mirror the LDAP NTLM path (transport::ldap): NetBIOS domain, upper-cased.
    let nt_domain = options
        .domain
        .split('.')
        .next()
        .unwrap_or(&options.domain)
        .to_uppercase();

    // A present-but-malformed hash is an error, not a silent fallback to
    // password (parse_hash returns None for both absent and malformed).
    let creds = if options.hashes.is_some() {
        let nt_hash = match parse_hash(options.hashes.as_deref()) {
            Some(h) => h,
            None => {
                error!("Invalid NT hash: expected 'LMHASH:NTHASH', ':NTHASH' or a bare 32-hex NT hash");
                return Err("invalid NT hash".into());
            }
        };
        debug!("ADWS auth: NTLM pass-the-hash as {nt_domain}\\{username}");
        Credentials::NtHash { domain: nt_domain, username, nt_hash }
    } else {
        let password = options
            .password
            .clone()
            .ok_or("ADWS requires a password (-p) or an NT hash (--hashes)")?;
        debug!("ADWS auth: NTLM password as {nt_domain}\\{username}");
        Credentials::Password { domain: nt_domain, username, password }
    };

    let mut target = Target::new(host, options.domain.clone());
    // --ldapport overrides the ADWS port when set; otherwise keep 9389.
    if let Some(port) = options.port {
        debug!("ADWS port set from --ldapport: {port}");
        target.port = port;
    }
    let client = AdwsClient::connect(target, creds)
        .await
        .map_err(|e| format!("ADWS connection failed: {e}"))?;

    info!(
        "Connected to {} Active Directory via ADWS (SOAP)!",
        options.domain.to_uppercase().bold().green()
    );
    Ok(AdwsTransport { client })
}

/// Reduce a `-u` value to the bare sAMAccountName, stripping a down-level
/// prefix (`DOMAIN\user`) and/or a UPN suffix (`user@domain`).
fn bare_sam(raw: &str) -> String {
    let after_prefix = raw.rsplit('\\').next().unwrap_or(raw);
    after_prefix
        .split('@')
        .next()
        .unwrap_or(after_prefix)
        .to_string()
}

#[async_trait]
impl DirectoryTransport for AdwsTransport {
    async fn naming_contexts(&mut self) -> Result<Vec<String>, Box<dyn Error>> {
        self.client
            .naming_contexts()
            .await
            .map_err(|e| format!("ADWS namingContexts failed: {e}").into())
    }

    async fn collect_context(
        &mut self,
        cn: &str,
        filter: &str,
        sink: &mut (dyn FnMut(LdapSearchEntry) -> Result<(), Box<dyn Error>> + Send),
    ) -> Result<usize, Box<dyn Error>> {
        // The adws-rs sink returns `()`, so capture the first sink error as a
        // Send-friendly String (keeps the async_trait future Send) and surface
        // it after the search completes.
        let mut sink_err: Option<String> = None;
        // Groups whose `member` came back at the MaxValRange cap: the search
        // cannot complete them (ADWS has no ranged retrieval), so defer them
        // and finish the membership with GetADGroupMember once the streaming
        // borrow on the client is released.
        let mut capped_groups: Vec<LdapSearchEntry> = Vec::new();

        let total = self
            .client
            .search_streaming(
                cn,
                Scope::Subtree,
                filter,
                ADWS_ATTRS,
                Some(SdFlags::OWNER_DACL), // Owner|DACL, like the LDAP collector
                true, // show-deleted, like the LDAP collector (tombstones + Deleted Objects)
                None, // Pull batch size: None => adws default (512)
                |e| {
                    if sink_err.is_some() {
                        return;
                    }
                    // adws_rs::SearchEntry and LdapSearchEntry share the
                    // { dn, attrs, bin_attrs } shape.
                    let entry = LdapSearchEntry {
                        dn: e.dn,
                        attrs: e.attrs,
                        bin_attrs: e.bin_attrs,
                    };
                    // A `member` list at/above MaxValRange is truncated: defer
                    // it for GetADGroupMember completion; forward the rest now.
                    let capped = entry
                        .attrs
                        .get("member")
                        .map(|v| v.len() >= MAX_VAL_RANGE)
                        .unwrap_or(false);
                    if capped {
                        capped_groups.push(entry);
                    } else if let Err(err) = sink(entry) {
                        sink_err = Some(err.to_string());
                    }
                },
            )
            .await
            .map_err(|e| format!("ADWS search on {cn} failed: {e}"))?;

        if let Some(msg) = sink_err {
            return Err(msg.into());
        }

        // Complete each deferred group's membership via the MS-ADCAP
        // `GetADGroupMember` custom action (not subject to MaxValRange), then
        // forward it. `recursive=false` keeps direct-member semantics, matching
        // the LDAP `member` attribute.
        for mut entry in capped_groups {
            match self.client.group_members(&entry.dn, false).await {
                Ok(members) => {
                    let before = entry.attrs.get("member").map(|v| v.len()).unwrap_or(0);
                    let dns: Vec<String> = members.into_iter().map(|m| m.dn).collect();
                    debug!(
                        "completed group {} membership over ADWS: {} => {} member(s)",
                        entry.dn,
                        before,
                        dns.len()
                    );
                    entry.attrs.insert("member".to_string(), dns);
                }
                Err(e) => {
                    warn!(
                        "GetADGroupMember failed for {}: {e}; keeping the capped member list",
                        entry.dn
                    );
                }
            }
            sink(entry)?;
        }

        Ok(total)
    }
}