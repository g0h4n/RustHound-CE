//! Session-collection module for RustHound-CE  (issue #46 - HasSession)
//! <https://bloodhound.specterops.io/resources/edges/has-session#hassession>
//! <https://github.com/g0h4n/HasSession-rs>
//!
//! Runs AFTER the LDAP phase, from `modules::run_modules`, and only when the
//! collection method actually contacts machines (i.e. NOT `DCOnly`).
//!
//! Three native RPC paths (all provided by the `dcerpc` crate), mapped to the
//! BloodHound CE computer schema:
//!
//!   SRVSVC / NetrSessionEnum   -> Computer.Sessions            (HasSession)
//!   WKSSVC / NetrWkstaUserEnum -> Computer.PrivilegedSessions  (LoggedOn)
//!   WINREG / HKEY_USERS        -> Computer.RegistrySessions    (LoggedOn)
//!
//! SharpHound-style behaviour baked in:
//!   * reachability pre-check on 445 with a hard timeout (skip dead hosts);
//!   * "active computer" filter based on pwdLastSet age (ComputerExpiryDays);
//!   * DCOnly never reaches this module;
//!   * bounded concurrency (throttle) instead of a serial loop;
//!   * names resolved to SIDs using the already-collected LDAP data.
//!
//! The target host is the computer FQDN (properties.name, from dNSHostName).
//! We do NOT use the fqdn->ip map: connections go to the FQDN and rely on DNS.
//!
//! Accessors this module needs (add them to RustHound-CE if missing):
//!   impl Computer          -> sessions_mut(), privileged_sessions_mut(),
//!                             registry_sessions_mut() : &mut Session
//!   impl ComputerProperties-> pwdlastset(&self) -> i64
//!   impl User              -> object_identifier(&self) -> &String

use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;

use futures::stream::{self, StreamExt};
use log::{debug, info, trace, warn};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};

use dcerpc::rrp::{RegistryClient, RegistrySession};
use dcerpc::srvsvc::SrvsvcClient;
use dcerpc::wkssvc::{WkstaUser, WkstaUserClient};
use smb2_client::SmbClient;
use crate::transport::smb::{connect_ipc, open_rpc_pipe, SmbAuth};

use crate::args::{CollectionMethod, Options};
use crate::objects::common::UserComputerSession;
use crate::objects::computer::Computer;
use crate::objects::user::User;

const DEFAULT_CONCURRENCY: usize = 10;      // ~ SharpHound --Throttle
const DEFAULT_PORT_TIMEOUT_MS: u64 = 1_500; // 445 pre-check budget
const DEFAULT_HOST_TIMEOUT_MS: u64 = 8_000; // whole per-host RPC budget
const DEFAULT_EXPIRY_DAYS: i64 = 60;        // ~ SharpHound --ComputerExpiryDays

// ----
// Raw per-host findings (kept close to HasSession-rs)
// ----

struct SmbSession { user: String, _client: String }

struct HostFindings {
    computer_sid: String,
    smb_sessions: Vec<SmbSession>,      // SRVSVC
    logged_on:    Vec<WkstaUser>,       // WKSSVC
    registry:     Vec<RegistrySession>, // WINREG
    errors:       Vec<String>,
}

// Entry point called by run_modules
pub async fn run(
    args:      &Options,
    users:     &[User],           // needed to resolve RPC principal names -> SIDs
    computers: &mut Vec<Computer>,
) -> Result<(), Box<dyn Error>> {
    // Hard guard: DCOnly must never touch a machine.
    if !args.collection_method.does_sessions() {
        debug!("[sessions] collection method does not contact hosts - skipping");
        return Ok(());
    }

    // 1) Build the name -> SID resolution table from the LDAP data collected upstream.
    let sid_index = build_sid_index(users);

    // 2) Select ACTIVE targets only (enabled + pwdLastSet within the expiry window).
    //    The host is the computer FQDN (properties.name); no fqdn->ip lookup.
    let expiry_days = DEFAULT_EXPIRY_DAYS;
    let targets: Vec<(String, String)> = computers
        .iter()
        .filter(|c| is_active(c, expiry_days))
        .map(|c| (c.properties().name().clone(), c.object_identifier().clone()))
        .collect();

    info!("[sessions] {} active target(s) after expiry/enabled filter", targets.len());

    // 3) Enumerate with bounded concurrency (throttle) instead of a serial loop.
    let sem = Arc::new(Semaphore::new(DEFAULT_CONCURRENCY));
    let domain = args.domain.clone();
    let user = args.username.clone().unwrap_or_default();
    let password = args.password.clone().unwrap_or_default();
    let nt_hash = parse_hash(args.hashes.as_deref()); // "LM:NT" | ":NT" | "NT" -> [u8;16]
    let method = args.collection_method.clone();

    let findings: Vec<HostFindings> = stream::iter(targets)
        .map(|(host, computer_sid)| {
            let (sem, domain, user, password, method) =
                (sem.clone(), domain.clone(), user.clone(), password.clone(), method.clone());
            let nt_hash = nt_hash;
            async move {
                let _permit = sem.acquire().await.unwrap();
                enumerate_host(&host, computer_sid, &domain, &user, &password,
                               nt_hash.as_ref(), &method).await
            }
        })
        .buffer_unordered(DEFAULT_CONCURRENCY)
        .collect()
        .await;

    // 4) Fold findings back into the matching Computer objects (resolving names -> SIDs).
    let mut total_sessions = 0usize;
    for hf in &findings {
        total_sessions += apply_findings(computers, hf, &sid_index, &args.domain);
        for e in &hf.errors { warn!("{e}"); }
    }
    info!("[sessions] {total_sessions} session(s) enumerated in total across {} host(s)",
          findings.len());

    Ok(())
}

// Per-host enumeration (adapted from HasSession-rs enumerate_host)
async fn enumerate_host(
    host: &str, computer_sid: String,
    domain: &str, user: &str, password: &str,
    nt_hash: Option<&[u8; 16]>,
    method: &CollectionMethod,
) -> HostFindings {
    // SharpHound-style reachability pre-check: 445 open within budget
    if !is_reachable(host, DEFAULT_PORT_TIMEOUT_MS).await {
        trace!("[{host}] 445/tcp unreachable - skip");
        return HostFindings {
            computer_sid,
            smb_sessions: Vec::new(), logged_on: Vec::new(), registry: Vec::new(),
            errors: vec![format!("{host}: 445/tcp unreachable")],
        };
    }

    // The RPC body accumulates into its OWN locals and returns them, so it never
    // aliases the outer findings the timeout wrapper also needs (avoids E0499).
    let work = async {
        let mut smb_sessions = Vec::new();
        let mut logged_on    = Vec::new();
        let mut registry     = Vec::new();
        let mut errors       = Vec::new();

        // Inner block uses `?` for the fatal connect/auth/tree steps; the error
        // is folded into `errors` instead of bubbling out of `work`.
        let fatal: Result<(), String> = async {

            // Using transport/smb.rs 
            let auth = match nt_hash {
                Some(h) => SmbAuth::Hash(h),
                None    => SmbAuth::Password(password),
            };
            let mut smb = connect_ipc(host, domain, user, auth).await
                .map_err(|e| format!("{host}: {e}"))?;

            if method.srvsvc() {
                match srvsvc_sessions(&mut smb, host).await {
                    Ok((_, 5)) => errors.push(format!("[{host}] SRVSVC rc=5 ACCESS_DENIED (hardened / non-admin)")),
                    Ok((s, _)) => smb_sessions = s,
                    Err(e)     => errors.push(format!("{host} SRVSVC: {e}")),
                }
            }
            if method.wkssvc() {
                match enum_wksta(&mut smb, host).await {
                    Ok((_, 5)) => errors.push(format!("[{host}] WKSSVC rc=5 (local admin required)")),
                    Ok((u, _)) => logged_on = dedup_wksta(u),
                    Err(e)     => errors.push(format!("{host} WKSSVC: {e}")),
                }
            }
            if method.registry() {
                match enum_registry(&mut smb, domain, user, password, nt_hash, host).await {
                    Ok(sids) => registry = sids,
                    Err(e)   => errors.push(format!("{host} WINREG: {e} (RemoteRegistry stopped?)")),
                }
            }
            Ok(())
        }.await;

        if let Err(e) = fatal { errors.push(e); }
        (smb_sessions, logged_on, registry, errors)
    };

    // whole-host budget so a slow-but-open host can't stall a worker
    match timeout(Duration::from_millis(DEFAULT_HOST_TIMEOUT_MS), work).await {
        Ok((smb_sessions, logged_on, registry, errors)) => HostFindings {
            computer_sid, smb_sessions, logged_on, registry, errors,
        },
        Err(_elapsed) => HostFindings {
            computer_sid,
            smb_sessions: Vec::new(), logged_on: Vec::new(), registry: Vec::new(),
            errors: vec![format!("{host}: per-host timeout")],
        },
    }
}

// Reachability + activity helpers
async fn is_reachable(host: &str, port_timeout_ms: u64) -> bool {
    matches!(
        timeout(Duration::from_millis(port_timeout_ms),
                TcpStream::connect(format!("{host}:445"))).await,
        Ok(Ok(_))
    )
}

/// enabled + pwdLastSet within the expiry window (~ SharpHound ComputerExpiryDays).
fn is_active(c: &Computer, expiry_days: i64) -> bool {
    if !*c.properties().enabled() { return false; }
    let pls = c.properties().pwdlastset(); // add: pub fn pwdlastset(&self) -> i64
    if pls <= 0 { return false; }
    let now = chrono::Utc::now().timestamp();
    now - pls < expiry_days * 86_400
}

// Isolated RPC calls (unchanged from HasSession-rs)
async fn srvsvc_sessions(smb: &mut SmbClient, host: &str) -> anyhow::Result<(Vec<SmbSession>, u32)> {
    let pipe = open_rpc_pipe(smb, host, "srvsvc").await?;
    let mut srv = SrvsvcClient::bind(smb, pipe).await?;
    let (sessions, rc) = srv.enum_sessions().await?;
    Ok((sessions.into_iter()
        .map(|s| SmbSession { user: s.user, _client: s.client }).collect(), rc))
}

async fn enum_wksta(smb: &mut SmbClient, host: &str) -> anyhow::Result<(Vec<WkstaUser>, u32)> {
    let pipe = open_rpc_pipe(smb, host, "wkssvc").await?;
    let mut wk = WkstaUserClient::bind(smb, pipe).await?;
    Ok(wk.enum_users().await?)
}

async fn enum_registry(smb: &mut SmbClient, domain: &str, user: &str,
                       password: &str, nt_hash: Option<&[u8; 16]>, host: &str)
    -> anyhow::Result<Vec<RegistrySession>>
{
    let mut reg = match nt_hash {
        Some(h) => RegistryClient::connect_hash(smb, domain, user, h, host).await
                       .map_err(|e| anyhow::anyhow!("{e}"))?,
        None    => RegistryClient::connect(smb, domain, user, password, host).await
                       .map_err(|e| anyhow::anyhow!("{e}"))?,
    };
    reg.logged_on_sids().await.map_err(|e| anyhow::anyhow!("{e}"))
}

/// Build the principal -> SID lookup from the users collected during LDAP.
///
/// `User::properties().name()` is already "SAMACCOUNTNAME@DOMAIN.FQDN" (UPPER),
/// which we key directly. We also index the bare SAMAccountName as a fallback,
/// because SRVSVC/WKSSVC hand back a bare username (no realm). Bare-SAM keys can
/// collide across trusted domains; the fully-qualified key is always tried first.
fn build_sid_index(users: &[User]) -> HashMap<String, String> {
    let mut idx = HashMap::with_capacity(users.len() * 2);
    for u in users {
        let sid = u.object_identifier().clone(); // add: pub fn object_identifier(&self) -> &String
        if sid.is_empty() { continue; }
        let upn = u.properties().name().to_uppercase(); // SAM@DOMAIN.FQDN
        if let Some(sam) = upn.split('@').next() {
            // bare SAM: keep the first mapping, do not let a later duplicate clobber it
            idx.entry(sam.to_string()).or_insert_with(|| sid.clone());
        }
        idx.insert(upn, sid);
    }
    idx
}

/// Resolve a principal string coming from an RPC call to a domain SID.
///
/// Handles "DOMAIN\\user", "DOMAIN/user" and bare "user"; drops empty / "?" /
/// machine ("$") principals. Tries the fully-qualified key first, then bare SAM.
fn resolve(raw: &str, idx: &HashMap<String, String>, domain: &str) -> Option<String> {
    let bare = raw.rsplit(['\\', '/']).next().unwrap_or(raw).trim();
    if bare.is_empty() || bare == "?" || bare.ends_with('$') {
        return None;
    }
    let sam = bare.to_uppercase();
    let upn = format!("{sam}@{}", domain.to_uppercase());
    idx.get(&upn).or_else(|| idx.get(&sam)).cloned()
}

/// Construct a { UserSID, ComputerSID } link (fields are private -> use mutators).
fn mk_link(user_sid: String, computer_sid: String) -> UserComputerSession {
    let mut ucs = UserComputerSession::new();
    *ucs.user_sid_mut() = user_sid;
    *ucs.computer_sid_mut() = computer_sid;
    ucs
}

/// De-duplicate WKSSVC logon sessions and drop machine accounts (noise on DCs).
fn dedup_wksta(users: Vec<WkstaUser>) -> Vec<WkstaUser> {
    use std::collections::BTreeSet;
    let mut seen = BTreeSet::new();
    users.into_iter()
        .filter(|u| !u.username.ends_with('$'))
        .filter(|u| seen.insert((u.logon_domain.clone(), u.username.clone())))
        .collect()
}

/// Write one host's findings into the matching Computer object, and return the
/// number of session links written for that host.
///
/// SRVSVC   -> Sessions            (resolve username -> UserSID)
/// WKSSVC   -> PrivilegedSessions  (resolve username -> UserSID)
/// WINREG   -> RegistrySessions    (r.sid is already a SID, no resolution)
///
/// Each block sets Collected = true; unresolved principals are logged at warn!
/// rather than silently dropped, matching SharpHound's behaviour.
fn apply_findings(
    computers: &mut [Computer],
    hf: &HostFindings,
    sid_index: &HashMap<String, String>,
    domain: &str,
) -> usize {
    let computer = match computers
        .iter_mut()
        .find(|c| c.object_identifier() == &hf.computer_sid)
    {
        Some(c) => c,
        None => {
            warn!("[sessions] no computer object for SID {}", hf.computer_sid);
            return 0;
        }
    };
    let comp_sid = hf.computer_sid.clone();
    let fqdn = computer.properties().name().clone(); // clone before the mutable borrows
    let mut count = 0usize;

    // SRVSVC -> Sessions
    {
        let s = computer.sessions_mut(); // add: pub fn sessions_mut(&mut self) -> &mut Session
        for sess in &hf.smb_sessions {
            match resolve(&sess.user, sid_index, domain) {
                Some(user_sid) => {
                    trace!("[SRVSVC] {} has session on {fqdn}", sess.user);
                    s.results_mut().push(mk_link(user_sid, comp_sid.clone()));
                    count += 1;
                }
                None => warn!("[{comp_sid}] unresolved SRVSVC principal '{}'", sess.user),
            }
        }
        *s.collected_mut() = true;
    }

    // WKSSVC -> PrivilegedSessions
    {
        let p = computer.privileged_sessions_mut(); // add: privileged_sessions_mut()
        for u in &hf.logged_on {
            match resolve(&u.username, sid_index, domain) {
                Some(user_sid) => {
                    trace!("[WKSSVC] {}\\{} has session on {fqdn}", u.logon_domain, u.username);
                    p.results_mut().push(mk_link(user_sid, comp_sid.clone()));
                    count += 1;
                }
                None => warn!("[{comp_sid}] unresolved WKSSVC principal '{}\\{}'",
                               u.logon_domain, u.username),
            }
        }
        *p.collected_mut() = true;
    }

    // WINREG -> RegistrySessions (SIDs already; no resolution needed)
    {
        let r = computer.registry_sessions_mut(); // add: registry_sessions_mut()
        for reg in &hf.registry {
            if reg.sid.is_empty() { continue; }
            trace!("[WINREG] {} has session on {fqdn}", reg.sid);
            r.results_mut().push(mk_link(reg.sid.clone(), comp_sid.clone()));
            count += 1;
        }
        *r.collected_mut() = true;
    }

    debug!("[sessions] Total {count} session(s) on {fqdn}");
    count
}

/// Parse a hash string into the 16-byte NT hash for pass-the-hash.
///
/// Accepts "LMHASH:NTHASH", ":NTHASH" or a bare 32-hex "NTHASH". Returns None
/// when absent or malformed (caller then falls back to password auth).
fn parse_hash(h: Option<&str>) -> Option<[u8; 16]> {
    let raw = h?.trim();
    let nt = raw.rsplit(':').next().unwrap_or(raw).trim();
    if nt.len() != 32 || !nt.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&nt[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}