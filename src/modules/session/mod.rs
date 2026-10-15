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
//! Authentication reuses the SMB transport: password, pass the hash, or a
//! Kerberos ticket (pass the ticket) when --kerberos is set. Kerberos material
//! is built per host, since the AP-REQ targets that host's cifs/<host> SPN.
//!
//! The target host is the computer FQDN (properties.name, from dNSHostName).
//! We do NOT use the fqdn->ip map: connections go to the FQDN and rely on DNS.

use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;

use futures::stream::{self, StreamExt};
use log::{debug, info, trace, warn};
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};

use dcerpc::rrp::{RegistryClient, RegistrySession};
use dcerpc::srvsvc::SrvsvcClient;
use dcerpc::wkssvc::{WkstaUser, WkstaUserClient};
use smb2_client::SmbClient;
use crate::transport::smb::{connect_ipc, is_reachable, open_rpc_pipe, smb_identity, SmbAuth};

use crate::args::{CollectionMethod, Options};
use crate::objects::common::{Session, UserComputerSession};
use crate::objects::computer::Computer;
use crate::objects::user::User;

const DEFAULT_CONCURRENCY: usize = 10;      // ~ SharpHound --Throttle
const DEFAULT_PORT_TIMEOUT_MS: u64 = 1_500; // 445 pre-check budget
const DEFAULT_HOST_TIMEOUT_MS: u64 = 8_000; // whole per-host RPC budget
const DEFAULT_EXPIRY_DAYS: i64 = 60;        // ~ SharpHound --ComputerExpiryDays
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_MORE_DATA: u32 = 234;

// ----
// Raw per-host findings (kept close to HasSession-rs)
// ----

struct SmbSession { user: String, _client: String }

/// Outcome of one RPC call on one host.
enum Call<T> {
    NotRun,         // not part of this collection method
    Pending,        // attempted, no result yet
    Done(Vec<T>),
    Failed(String), // the error that is logged and written as FailureReason
}

impl<T> Call<T> {
    fn items(&self) -> &[T] {
        match self {
            Call::Done(v) => v,
            _ => &[],
        }
    }
}

struct HostFindings {
    computer_sid: String,
    smb_sessions: Call<SmbSession>,      // SRVSVC
    logged_on:    Call<WkstaUser>,       // WKSSVC
    registry:     Call<RegistrySession>, // WINREG
}

impl HostFindings {
    /// Every call the collection method makes starts as Pending.
    fn new(computer_sid: String, method: &CollectionMethod) -> Self {
        fn pending<T>(run: bool) -> Call<T> { if run { Call::Pending } else { Call::NotRun } }
        HostFindings {
            computer_sid,
            smb_sessions: pending(method.srvsvc()),
            logged_on:    pending(method.wkssvc()),
            registry:     pending(method.registry()),
        }
    }

    /// Mark the calls that have no result yet as failed (unreachable host,
    /// connect/auth failure, per-host timeout). Finished calls are kept.
    fn fail_pending(&mut self, reason: &str) {
        fn fail<T>(c: &mut Call<T>, reason: &str) {
            if matches!(c, Call::Pending) { *c = Call::Failed(reason.to_string()); }
        }
        fail(&mut self.smb_sessions, reason);
        fail(&mut self.logged_on, reason);
        fail(&mut self.registry, reason);
    }

    /// Distinct failure reasons, for the log (a connect failure is shared by all calls).
    fn errors(&self) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::new();
        for r in [failure(&self.smb_sessions), failure(&self.logged_on), failure(&self.registry)]
            .into_iter().flatten()
        {
            if !out.contains(&r) { out.push(r); }
        }
        out
    }
}

fn failure<T>(c: &Call<T>) -> Option<&str> {
    match c {
        Call::Failed(r) => Some(r),
        _ => None,
    }
}

// Entry point called by run_modules
pub async fn run(
    args:      &Options,
    users:     &[User],           // needed to resolve RPC principal names -> SIDs
    computers: &mut Vec<Computer>,
) -> Result<(), Box<dyn Error>> {
    // Hard guard: DCOnly must never touch a machine.
    if !args.collection_method.does_session() {
        debug!("[sessions] collection method does not contact hosts - skipping");
        return Ok(());
    }

    // 1) Build the name -> SID resolution table from the LDAP data collected upstream.
    trace!("[sessions] building SID index from {} user(s)", users.len());
    let sid_index = build_sid_index(users);
    trace!("[sessions] SID index built");

    // 2) Select ACTIVE targets only (enabled + pwdLastSet within the expiry window).
    //    The host is the computer FQDN (properties.name); no fqdn->ip lookup.
    let expiry_days = DEFAULT_EXPIRY_DAYS;
    let targets: Vec<(String, String)> = computers
        .iter()
        .filter(|c| c.is_active(expiry_days))
        .map(|c| (c.properties().name().clone(), c.object_identifier().clone()))
        .collect();

    info!("[sessions] {} active target(s) after expiry/enabled filter", targets.len());
    for (h, _) in &targets {
        trace!("[sessions] target host: {h}");
    }

    // 3) Enumerate with bounded concurrency (throttle) instead of a serial loop.
    let sem = Arc::new(Semaphore::new(DEFAULT_CONCURRENCY));
    // SMB sign-in identity: the account's own domain from -u, else --domain.
    let (signin_domain, user) = smb_identity(args.username.as_deref().unwrap_or_default(), &args.domain);
    let password = args.password.clone().unwrap_or_default();
    let nt_hash = parse_hash(args.hashes.as_deref()); // "LM:NT" | ":NT" | "NT" -> [u8;16]
    let method = args.collection_method.clone();

    // Kerberos: ccache path from KRB5CCNAME when --kerberos is set (computed once).
    let kerberos_ccache: Option<String> = if args.kerberos {
        std::env::var("KRB5CCNAME").ok()
    } else {
        None
    };
    // KDC (the DC) to request cifs/<host> service tickets from: FQDN, else IP, else domain.
    let kdc: String = args
        .ldapfqdn
        .clone()
        .filter(|s| !s.is_empty())
        .or_else(|| args.ip.clone())
        .unwrap_or_else(|| args.domain.clone());

    trace!("[sessions] starting concurrent enumeration (concurrency={DEFAULT_CONCURRENCY})");
    let findings: Vec<HostFindings> = stream::iter(targets)
        .map(|(host, computer_sid)| {
            let (sem, signin_domain, user, password, method) =
                (sem.clone(), signin_domain.clone(), user.clone(), password.clone(), method.clone());
            let nt_hash = nt_hash;
            let kerberos_ccache = kerberos_ccache.clone();
            let kdc = kdc.clone();
            async move {
                trace!("[sessions] [{host}] task scheduled, awaiting concurrency permit");
                let _permit = sem.acquire().await.unwrap();
                trace!("[sessions] [{host}] permit acquired, entering enumerate_host");
                let hf = enumerate_host(
                    &host, computer_sid, &signin_domain, &user, &password,
                    nt_hash.as_ref(), kerberos_ccache.as_deref(), &kdc, &method,
                ).await;
                trace!("[sessions] [{host}] enumerate_host returned ({} error(s))", hf.errors().len());
                hf
            }
        })
        .buffer_unordered(DEFAULT_CONCURRENCY)
        .collect()
        .await;

    trace!("[sessions] all {} host task(s) completed, folding findings", findings.len());

    // 4) Fold findings back into the matching Computer objects (resolving names -> SIDs).
    let mut total_sessions = 0usize;
    for hf in &findings {
        total_sessions += apply_findings(computers, hf, &sid_index, &args.domain);
        for e in hf.errors() { warn!("{e}"); }
    }
    info!("[sessions] {total_sessions} session(s) enumerated in total across {} host(s)",
          findings.len());

    Ok(())
}

// Per-host enumeration (adapted from HasSession-rs enumerate_host)
#[allow(clippy::too_many_arguments)]
async fn enumerate_host(
    host: &str, computer_sid: String,
    signin_domain: &str, user: &str, password: &str,
    nt_hash: Option<&[u8; 16]>,
    kerberos_ccache: Option<&str>,
    kdc: &str,
    method: &CollectionMethod,
) -> HostFindings {
    trace!("[sessions] [{host}] enumerate_host: begin, running 445 pre-check");
    let mut hf = HostFindings::new(computer_sid, method);

    // SharpHound-style reachability pre-check: 445 open within budget
    if !is_reachable(host, DEFAULT_PORT_TIMEOUT_MS).await {
        trace!("[{host}] 445/tcp unreachable - skip");
        hf.fail_pending(&format!("{host}: 445/tcp unreachable"));
        return hf;
    }

    // The RPC body writes each call's outcome into `hf` as soon as it finishes,
    // so a per-host timeout keeps the calls that already completed.
    let work = async {
        // Inner block uses `?` for the fatal connect/auth/tree steps; the error
        // becomes the FailureReason of every call that hasn't run yet.
        let fatal: Result<(), String> = async {
            // connect + SESSION_SETUP: Kerberos ticket, or password / pass the hash.
            let mut smb = if let Some(ccache) = kerberos_ccache {
                // Kerberos: build a cifs/<host> ticket for THIS host.
                let spn = format!("cifs/{host}");
                let (gss_blob, session_key) =
                    crate::transport::kerberos::kerberos_material_for(ccache, &spn, kdc)
                        .await
                        .map_err(|e| format!("{host} krb: {e}"))?;
                let auth = SmbAuth::Kerberos { gss_blob: &gss_blob, session_key: &session_key };
                connect_ipc(host, signin_domain, user, auth).await.map_err(|e| format!("{host}: {e}"))?
            } else {
                let auth = match nt_hash {
                    Some(h) => SmbAuth::Hash(h),
                    None    => SmbAuth::Password(password),
                };
                connect_ipc(host, signin_domain, user, auth).await.map_err(|e| format!("{host}: {e}"))?
            };

            if method.srvsvc() {
                hf.smb_sessions = match srvsvc_sessions(&mut smb, host).await {
                    Ok((s, rc)) => from_rc(s, rc, &format!("[{host}] SRVSVC"), "ACCESS_DENIED (hardened / non-admin)"),
                    Err(e)      => Call::Failed(format!("{host} SRVSVC: {e}")),
                };
            }
            if method.wkssvc() {
                hf.logged_on = match enum_wksta(&mut smb, host).await {
                    Ok((u, rc)) => from_rc(dedup_wksta(u), rc, &format!("[{host}] WKSSVC"), "(local admin required)"),
                    Err(e)      => Call::Failed(format!("{host} WKSSVC: {e}")),
                };
            }
            if method.registry() {
                hf.registry = match enum_registry(&mut smb, signin_domain, user, password, nt_hash, host).await {
                    Ok(sids) => Call::Done(sids),
                    Err(e)   => Call::Failed(format!("{host} WINREG: {e} (RemoteRegistry stopped?)")),
                };
            }
            Ok(())
        }.await;

        if let Err(e) = fatal { hf.fail_pending(&e); }
    };

    // whole-host budget so a slow-but-open host can't stall a worker
    if timeout(Duration::from_millis(DEFAULT_HOST_TIMEOUT_MS), work).await.is_err() {
        hf.fail_pending(&format!("{host}: per-host timeout"));
    }
    hf
}

/// Map a NetrSessionEnum / NetrWkstaUserEnum return code onto the call outcome.
/// 234 keeps the entries returned, as SharpHound does; dcerpc has no resume handle.
fn from_rc<T>(items: Vec<T>, rc: u32, call: &str, denied_hint: &str) -> Call<T> {
    if rc == ERROR_MORE_DATA {
        debug!("{call} rc=234 ERROR_MORE_DATA, keeping the {} entries returned", items.len());
    }
    match rc {
        0 | ERROR_MORE_DATA => Call::Done(items),
        ERROR_ACCESS_DENIED => Call::Failed(format!("{call} rc=5 {denied_hint}")),
        _ => Call::Failed(format!("{call} rc={rc}")),
    }
}

// Reachability + activity helpers moved to transport::smb::is_reachable
// and Computer::is_active (shared with the local-group and webclient modules).

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
        let sid = u.object_identifier().clone();
        if sid.is_empty() { continue; }
        let upn = u.properties().name().to_uppercase(); // SAM@DOMAIN.FQDN
        if let Some(sam) = upn.split('@').next() {
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
/// Each list gets Collected / FailureReason from its own call (`set_status`);
/// unresolved principals are logged at warn! rather than silently dropped,
/// matching SharpHound's behaviour.
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
        let s = computer.sessions_mut();
        for sess in hf.smb_sessions.items() {
            match resolve(&sess.user, sid_index, domain) {
                Some(user_sid) => {
                    trace!("[SRVSVC] {} has session on {fqdn}", sess.user);
                    s.results_mut().push(mk_link(user_sid, comp_sid.clone()));
                    count += 1;
                }
                None => warn!("[{comp_sid}] unresolved SRVSVC principal '{}'", sess.user),
            }
        }
        set_status(s, &hf.smb_sessions);
    }

    // WKSSVC -> PrivilegedSessions
    {
        let p = computer.privileged_sessions_mut();
        for u in hf.logged_on.items() {
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
        set_status(p, &hf.logged_on);
    }

    // WINREG -> RegistrySessions (SIDs already; no resolution needed)
    {
        let r = computer.registry_sessions_mut();
        for reg in hf.registry.items() {
            if reg.sid.is_empty() { continue; }
            trace!("[WINREG] {} has session on {fqdn}", reg.sid);
            r.results_mut().push(mk_link(reg.sid.clone(), comp_sid.clone()));
            count += 1;
        }
        set_status(r, &hf.registry);
    }

    debug!("[sessions] Total {count} session(s) on {fqdn}");
    count
}

/// Collected / FailureReason of one session list: Collected only when its call
/// succeeded, FailureReason only when it failed (a call not made leaves both unset).
fn set_status<T>(s: &mut Session, call: &Call<T>) {
    *s.collected_mut() = matches!(call, Call::Done(_));
    *s.failure_reason_mut() = failure(call).map(str::to_string);
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

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "ws01.example.local";
    const COMPUTER_SID: &str = "S-1-5-21-1111-2222-3333-1105";

    fn smb(user: &str) -> SmbSession {
        SmbSession { user: user.to_string(), _client: String::new() }
    }

    fn status(s: &Session) -> (bool, Option<&str>) {
        (*s.collected(), s.failure_reason().as_deref())
    }

    #[test]
    fn session_defaults_to_not_collected() {
        assert_eq!(status(&Session::default()), (false, None));
        assert_eq!(status(&Session::new()), (false, None));
        let s: Session = serde_json::from_str(r#"{"Results":[],"FailureReason":null}"#).unwrap();
        assert_eq!(status(&s), (false, None));
    }

    #[test]
    fn return_codes() {
        assert!(matches!(from_rc(vec![smb("alice")], 0, "SRVSVC", ""), Call::Done(v) if v.len() == 1));
        // ERROR_MORE_DATA keeps the entries returned, like SharpHound
        assert!(matches!(from_rc(vec![smb("alice")], 234, "SRVSVC", ""), Call::Done(v) if v.len() == 1));
        assert!(matches!(from_rc(vec![smb("alice")], 5, "[h] WKSSVC", "(local admin required)"),
            Call::Failed(r) if r == "[h] WKSSVC rc=5 (local admin required)"));
        // any other non-zero code is a failure, entries or not
        assert!(matches!(from_rc(vec![smb("alice")], 53, "[h] SRVSVC", ""),
            Call::Failed(r) if r == "[h] SRVSVC rc=53"));
        assert!(matches!(from_rc(Vec::<SmbSession>::new(), 1722, "[h] SRVSVC", ""),
            Call::Failed(r) if r == "[h] SRVSVC rc=1722"));
    }

    #[test]
    fn only_the_calls_of_the_method_are_attempted() {
        let hf = HostFindings::new(COMPUTER_SID.to_string(), &CollectionMethod::All);
        assert!(matches!(hf.smb_sessions, Call::Pending));
        assert!(matches!(hf.logged_on, Call::Pending));
        assert!(matches!(hf.registry, Call::Pending));

        let hf = HostFindings::new(COMPUTER_SID.to_string(), &CollectionMethod::RegistryOnly);
        assert!(matches!(hf.smb_sessions, Call::NotRun));
        assert!(matches!(hf.logged_on, Call::NotRun));
        assert!(matches!(hf.registry, Call::Pending));
    }


    #[test]
    fn timeout_keeps_finished_calls() {
        let mut hf = HostFindings::new(COMPUTER_SID.to_string(), &CollectionMethod::All);
        hf.smb_sessions = Call::Done(vec![smb("alice")]);
        let reason = format!("{HOST}: per-host timeout");
        hf.fail_pending(&reason);

        let (mut s, mut p, mut r) = (Session::default(), Session::default(), Session::default());
        set_status(&mut s, &hf.smb_sessions);
        set_status(&mut p, &hf.logged_on);
        set_status(&mut r, &hf.registry);
        assert_eq!(status(&s), (true, None));
        assert_eq!(status(&p), (false, Some(reason.as_str())));
        assert_eq!(status(&r), (false, Some(reason.as_str())));
        assert_eq!(hf.smb_sessions.items().len(), 1);
        assert_eq!(hf.errors(), vec![reason.as_str()]);
    }

    #[test]
    fn unreachable_fails_only_the_attempted_calls() {
        let mut hf = HostFindings::new(COMPUTER_SID.to_string(), &CollectionMethod::RegistryOnly);
        let reason = format!("{HOST}: 445/tcp unreachable");
        hf.fail_pending(&reason);

        let (mut s, mut r) = (Session::default(), Session::default());
        set_status(&mut s, &hf.smb_sessions);
        set_status(&mut r, &hf.registry);
        assert_eq!(status(&s), (false, None));
        assert_eq!(status(&r), (false, Some(reason.as_str())));
    }

    #[test]
    fn errors_are_listed_once() {
        let mut hf = HostFindings::new(COMPUTER_SID.to_string(), &CollectionMethod::All);
        hf.logged_on = Call::Failed("[h] WKSSVC rc=5 (local admin required)".to_string());
        hf.fail_pending("h: connect failed");
        assert_eq!(hf.errors(), vec!["h: connect failed", "[h] WKSSVC rc=5 (local admin required)"]);
    }
}
