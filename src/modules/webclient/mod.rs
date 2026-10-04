//! WebClient / WebDAV service probe for RustHound-CE (issue #72 - IsWebClientRunning)
//! <https://github.com/g0h4n/IsWebClientRunning-rs>
//!
//! Runs AFTER the LDAP phase, from `modules::run_modules`, and only when the
//! collection method contacts machines (NOT DCOnly / LdapOnly).
//!
//!   SMB / CREATE \PIPE\DAV RPC SERVICE on IPC$ -> Computer.IsWebClientRunning
//!
//! A host with the WebClient (WebDAV) service running can be coerced to
//! authenticate over HTTP and relayed to AD CS web enrollment: it is an ESC8
//! relay candidate. Combined with the HttpEnrollmentEndpoints probe, this closes
//! the two preconditions BloodHound needs to light up the coercion/ESC8 path.
//!
//! Same SharpHound-style behaviour as the sessions and local-group modules:
//! 445 pre-check (`transport::smb::is_reachable`), active-computer filter
//! (`Computer::is_active`), bounded concurrency, no machine contact under
//! DCOnly. Authentication reuses the SMB transport (password, pass the hash,
//! pass the ticket), so nothing new is needed there. The detection stops one
//! step earlier than LocalGroups: no DCE/RPC bind, no opnum, just the CREATE.

pub mod scanner;
pub mod types;

use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;

use futures::stream::{self, StreamExt};
use log::{debug, info, trace};
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};

use crate::args::Options;
use crate::modules::webclient::types::Outcome;
use crate::objects::common::WebClientRunning;
use crate::objects::computer::Computer;
use crate::transport::smb::{connect_ipc, is_reachable, nt_hash_from_str, smb_user, SmbAuth};

const DEFAULT_CONCURRENCY: usize = 10;      // ~ SharpHound --Throttle
const DEFAULT_PORT_TIMEOUT_MS: u64 = 1_500; // 445 pre-check budget
const DEFAULT_HOST_TIMEOUT_MS: u64 = 8_000; // whole per-host budget
const DEFAULT_EXPIRY_DAYS: i64 = 60;        // ~ SharpHound --ComputerExpiryDays

/// Entry point called by run_modules.
pub async fn run(
    args: &Options,
    computers: &mut Vec<Computer>,
) -> Result<(), Box<dyn Error>> {
    // Hard guard: DCOnly / LdapOnly must never touch a machine.
    if !args.collection_method.does_web_client() {
        debug!("[webclient] collection method does not contact hosts - skipping");
        return Ok(());
    }

    // Select ACTIVE targets only (enabled + pwdLastSet within the expiry window).
    // The host is the computer FQDN (properties.name); no fqdn->ip lookup.
    let targets: Vec<(String, String)> = computers
        .iter()
        .filter(|c| c.is_active(DEFAULT_EXPIRY_DAYS))
        .map(|c| (c.properties().name().clone(), c.object_identifier().clone()))
        .collect();

    info!("[webclient] {} active target(s) after expiry/enabled filter", targets.len());
    if targets.is_empty() {
        return Ok(());
    }

    // Auth material, computed once and cloned per host.
    let sem = Arc::new(Semaphore::new(DEFAULT_CONCURRENCY));
    let domain = args.domain.clone();
    let user = smb_user(args.username.as_deref().unwrap_or_default());
    let password = args.password.clone().unwrap_or_default();
    let nt_hash = nt_hash_from_str(args.hashes.as_deref().unwrap_or_default());

    // Kerberos: ccache path from KRB5CCNAME when --kerberos is set.
    let kerberos_ccache: Option<String> = if args.kerberos {
        std::env::var("KRB5CCNAME").ok()
    } else {
        None
    };
    // KDC (the DC) to request cifs/<host> service tickets from.
    let kdc: String = args
        .ldapfqdn
        .clone()
        .filter(|s| !s.is_empty())
        .or_else(|| args.ip.clone())
        .unwrap_or_else(|| args.domain.clone());

    // Probe with bounded concurrency.
    let results: Vec<(String, Outcome)> = stream::iter(targets)
        .map(|(host, oid)| {
            let (sem, domain, user, password) =
                (sem.clone(), domain.clone(), user.clone(), password.clone());
            let nt_hash = nt_hash;
            let kerberos_ccache = kerberos_ccache.clone();
            let kdc = kdc.clone();
            async move {
                let _permit = sem.acquire().await.unwrap();
                let outcome = probe_host(
                    &host, &domain, &user, &password,
                    nt_hash.as_ref(), kerberos_ccache.as_deref(), &kdc,
                ).await;
                (oid, outcome)
            }
        })
        .buffer_unordered(DEFAULT_CONCURRENCY)
        .collect()
        .await;

    // Fold results back onto the matching Computer objects.
    let mut running = 0usize;
    let mut map: HashMap<String, WebClientRunning> = HashMap::with_capacity(results.len());
    for (oid, outcome) in &results {
        if outcome.is_running() {
            running += 1;
        }
        if let Some(reason) = outcome.failure_reason() {
            debug!("[webclient] {oid}: {reason}");
        }
        map.insert(oid.clone(), api_result(outcome));
    }
    for c in computers.iter_mut() {
        if let Some(v) = map.remove(c.object_identifier()) {
            c.set_is_web_client_running(v);
        }
    }

    info!("[webclient] WebClient running on {running}/{} probed host(s)",results.len());
    Ok(())
}

/// Convert a probe [`Outcome`] into the serialisable `IsWebClientRunning` wrapper.
fn api_result(o: &Outcome) -> WebClientRunning {
    WebClientRunning {
        result: o.is_running(),
        collected: o.collected(),
        failure_reason: o.failure_reason(),
    }
}

/// Probe one host: 445 pre-check, connect IPC$ (password / hash / ticket), then
/// the WebDAV pipe CREATE, under a whole-host timeout.
#[allow(clippy::too_many_arguments)]
async fn probe_host(
    host: &str,
    domain: &str,
    user: &str,
    password: &str,
    nt_hash: Option<&[u8; 16]>,
    kerberos_ccache: Option<&str>,
    kdc: &str,
) -> Outcome {
    // SharpHound-style reachability pre-check: 445 open within budget.
    if !is_reachable(host, DEFAULT_PORT_TIMEOUT_MS).await {
        trace!("[{host}] 445/tcp unreachable - skip");
        return Outcome::Unreachable(format!("{host}: 445/tcp unreachable"));
    }

    let work = async {
        // connect + SESSION_SETUP + tree-connect IPC$: Kerberos, or password / PtH.
        let mut smb = if let Some(ccache) = kerberos_ccache {
            let spn = format!("cifs/{host}");
            let (gss_blob, session_key) =
                match crate::transport::kerberos::kerberos_material_for(ccache, &spn, kdc).await {
                    Ok(m) => m,
                    Err(e) => return Outcome::AuthFailed(format!("{host} krb: {e}")),
                };
            let auth = SmbAuth::Kerberos { gss_blob: &gss_blob, session_key: &session_key };
            match connect_ipc(host, domain, user, auth).await {
                Ok(c) => c,
                Err(e) => return connect_error(host, &e),
            }
        } else {
            let auth = match nt_hash {
                Some(h) => SmbAuth::Hash(h),
                None => SmbAuth::Password(password),
            };
            match connect_ipc(host, domain, user, auth).await {
                Ok(c) => c,
                Err(e) => return connect_error(host, &e),
            }
        };

        debug!("[{host}] IPC$ ready, probing WebClient pipe");
        scanner::probe(&mut smb, host).await
    };

    // Whole-host budget so a slow-but-open host can't stall a worker.
    match timeout(Duration::from_millis(DEFAULT_HOST_TIMEOUT_MS), work).await {
        Ok(outcome) => outcome,
        Err(_) => Outcome::Unreachable(format!("{host}: per-host timeout")),
    }
}

/// Map a `connect_ipc` failure (anyhow with a stable prefix set by
/// `transport::smb`) onto the right [`Outcome`] bucket.
fn connect_error(host: &str, e: &anyhow::Error) -> Outcome {
    let msg = format!("{host}: {e}");
    let s = e.to_string();
    if s.starts_with("auth") {
        Outcome::AuthFailed(msg)
    } else if s.starts_with("connect:") {
        Outcome::Unreachable(msg)
    } else if s.contains("tree connect") {
        // IPC$ refused: usually a hardened host, not a credential problem.
        Outcome::AccessDenied(msg)
    } else {
        Outcome::Error(msg)
    }
}