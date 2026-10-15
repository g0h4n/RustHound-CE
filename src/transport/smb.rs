//! SMB transport for RustHound-CE.
//!
//! `connect_authenticated` only does TCP 445 and the NTLM SESSION_SETUP, then
//! hands back an authenticated SmbClient with no tree bound. Callers then tree
//! connect the share they need:
//!   * IPC$   for MS RPC pipes (SRVSVC, WKSSVC, WINREG) used by the sessions
//!            module,
//!   * SYSVOL to read GPO files (GptTmpl.inf, Groups.xml) used by the gpo
//!            module.
//! The SmbClient keeps a single active tree, so switch shares by calling
//! `tree_connect` again on the same client.
//!
//! Every SMB step is logged. Use RUST_LOG=trace for the full detail.

use log::{debug, error, trace, warn};
use smb2_client::{SmbClient, SmbError};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

pub use smb2_client::msg::DirEntry;


/// STATUS_OBJECT_PATH_NOT_FOUND (intermediate directory missing).
const OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;

/// Credentials used for the SMB SESSION_SETUP.
pub enum SmbAuth<'a> {
    /// NTLMv2 with a clear text password.
    Password(&'a str),
    /// Pass the hash with a raw 16 byte NT hash.
    Hash(&'a [u8; 16]),
    /// Pass-the-ticket: SPNEGO AP-REQ blob + 16 byte SMB session key
    /// already built for this host's cifs/<host> SPN.
    Kerberos { gss_blob: &'a [u8], session_key: &'a [u8; 16] },
}

/// UNC of the IPC$ share (MS RPC pipes).
pub fn ipc_unc(host: &str) -> String {
    format!(r"\\{host}\IPC$")
}

/// UNC of the SYSVOL share (GPO files).
pub fn sysvol_unc(host: &str) -> String {
    format!(r"\\{host}\SYSVOL")
}

/// Connect to host:445 and authenticate. No tree is bound yet.
///
/// Returns an authenticated SmbClient. Call `tree_connect` (or one of the
/// `connect_ipc` / `connect_sysvol` helpers) before doing any share work.
pub async fn connect_authenticated(
    host: &str,
    domain: &str,
    user: &str,
    auth: SmbAuth<'_>,
) -> anyhow::Result<SmbClient> {
    let target = format!("{host}:445");

    // TCP connect and SMB negotiate.
    trace!("[{host}] SMB connecting to {target}");
    let mut smb = SmbClient::connect(&target).await.map_err(|e| {
        error!("[{host}] SMB connect failed: {e}");
        anyhow::anyhow!("connect: {e}")
    })?;
    debug!("[{host}] SMB connected, negotiate done");

    // SESSION_SETUP: password or pass the hash.
    match auth {
        SmbAuth::Hash(nt) => {
            trace!("[{host}] SMB SESSION_SETUP as {domain}\\{user} (pass the hash)");
            smb.login_hash(host, domain, user, nt).await.map_err(|e| {
                error!("[{host}] SMB auth failed for {domain}\\{user} (pass the hash): {e}");
                anyhow::anyhow!("auth(PTH): {e}")
            })?;
        }
        SmbAuth::Password(password) => {
            trace!("[{host}] SMB SESSION_SETUP as {domain}\\{user} (password)");
            smb.login(host, domain, user, password).await.map_err(|e| {
                error!("[{host}] SMB auth failed for {domain}\\{user}: {e}");
                anyhow::anyhow!("auth: {e}")
            })?;
        }
        SmbAuth::Kerberos { gss_blob, session_key } => {
            trace!("[{host}] SMB SESSION_SETUP with Kerberos (pass the ticket)");
            smb.login_kerberos(gss_blob, session_key).await.map_err(|e| {
                error!("[{host}] SMB Kerberos auth failed: {e}");
                anyhow::anyhow!("auth(krb): {e}")
            })?;
        }
    }
    debug!("[{host}] SMB authenticated as {domain}\\{user}");

    Ok(smb)
}

/// Tree connect a share on an already authenticated client.
///
/// The client keeps a single active tree, so calling this again switches the
/// client from one share to another (for example IPC$ then SYSVOL).
pub async fn tree_connect(smb: &mut SmbClient, host: &str, unc: &str) -> anyhow::Result<()> {
    trace!("[{host}] SMB tree connect {unc}");
    smb.tree_connect(unc).await.map_err(|e| {
        error!("[{host}] SMB tree connect to {unc} failed: {e}");
        anyhow::anyhow!("tree connect {unc}: {e}")
    })?;
    debug!("[{host}] tree connected: {unc}");
    Ok(())
}

/// Connect, authenticate and tree connect IPC$ (ready for RPC pipes).
pub async fn connect_ipc(
    host: &str,
    domain: &str,
    user: &str,
    auth: SmbAuth<'_>,
) -> anyhow::Result<SmbClient> {
    let mut smb = connect_authenticated(host, domain, user, auth).await?;
    tree_connect(&mut smb, host, &ipc_unc(host)).await?;
    debug!("[{host}] IPC$ ready, RPC pipes available");
    Ok(smb)
}

/// Connect, authenticate and tree connect SYSVOL (ready for GPO file reads).
pub async fn connect_sysvol(
    host: &str,
    domain: &str,
    user: &str,
    auth: SmbAuth<'_>,
) -> anyhow::Result<SmbClient> {
    let mut smb = connect_authenticated(host, domain, user, auth).await?;
    tree_connect(&mut smb, host, &sysvol_unc(host)).await?;
    debug!("[{host}] SYSVOL ready, GPO files readable");
    Ok(smb)
}

/// Open a named MS RPC pipe over the connected tree and return its file id.
///
/// Thin wrapper over SmbClient::open_pipe that adds log context. A failure here
/// is usually a missing or stopped service, so it is logged at warn.
pub async fn open_rpc_pipe(
    smb: &mut SmbClient,
    host: &str,
    pipe: &str,
) -> anyhow::Result<[u8; 16]> {
    trace!("[{host}] opening RPC pipe {pipe}");
    match smb.open_pipe(pipe).await {
        Ok(file_id) => {
            debug!("[{host}] RPC pipe {pipe} opened");
            Ok(file_id)
        }
        Err(e) => {
            warn!("[{host}] cannot open RPC pipe {pipe}: {e}");
            Err(anyhow::anyhow!("{pipe}: {e}"))
        }
    }
}

/// List a directory on the connected disk share.
///
/// `path` is relative to the share root ("" for the root). Excludes "." and
/// "..". Tree-connect the share first (see `connect_sysvol`).
pub async fn list_dir(smb: &mut SmbClient, host: &str, path: &str) -> anyhow::Result<Vec<DirEntry>> {
    let shown = if path.is_empty() { r"\" } else { path };
    trace!("[{host}] SMB list dir {shown}");
    smb.list_directory(path).await.map_err(|e| {
        warn!("[{host}] cannot list {shown}: {e}");
        anyhow::anyhow!("list {shown}: {e}")
    })
}

/// Read a file off the connected share.
///
/// Returns Ok(None) when the file (or an intermediate directory) does not
/// exist, which is expected on SYSVOL where most GPOs carry no GptTmpl.inf or
/// Groups.xml. Warns only on a real failure.
pub async fn try_read_file(
    smb: &mut SmbClient,
    host: &str,
    path: &str,
) -> anyhow::Result<Option<Vec<u8>>> {
    use smb2_client::status;
    trace!("[{host}] SMB read file {path}");
    match smb.read_file(path).await {
        Ok(bytes) => Ok(Some(bytes)),
        Err(SmbError::Status(code, _))
            if code == status::OBJECT_NAME_NOT_FOUND || code == OBJECT_PATH_NOT_FOUND =>
        {
            trace!("[{host}] {path} not present, skipping");
            Ok(None)
        }
        Err(e) => {
            warn!("[{host}] cannot read {path}: {e}");
            Err(anyhow::anyhow!("read {path}: {e}"))
        }
    }
}

/// Parse an "LMHASH:NTHASH" / ":NTHASH" / "NTHASH" string into the 16 byte NT
/// hash. Shared by the sessions and gpo modules.
pub fn nt_hash_from_str(raw: &str) -> Option<[u8; 16]> {
    let nt = raw.trim().rsplit(':').next().unwrap_or(raw).trim();
    if nt.len() != 32 || !nt.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&nt[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Split a raw `-u/--ldapusername` value into the `(domain, user)` pair
/// expected by SMB SESSION_SETUP.
///
/// `smb.login()`/`login_hash()` build the NTLM identity themselves as
/// `domain + "\" + user`, so the user must be the bare name (passing
/// `j.harris@scaffold.htb` through gave `SCAFFOLD.HTB\j.harris@scaffold.htb`
/// and STATUS_LOGON_FAILURE). The domain is the one the username names
/// (`DOMAIN\user` -> `DOMAIN`, `user@domain` -> `domain`), else
/// `default_domain` (`--domain`), so an account from another domain signs in
/// to its own. LDAP's bind (transport::ldap) handles its own format and must
/// not use this helper.
pub fn smb_identity(raw: &str, default_domain: &str) -> (String, String) {
    let raw = raw.trim();
    // A UPN splits at its last '@', as Windows does.
    let (no_upn, upn_domain) = match raw.rsplit_once('@') {
        Some((user, domain)) => (user, Some(domain)),
        None => (raw, None),
    };
    let (bare, netbios_domain) = match no_upn.rsplit_once('\\') {
        Some((domain, user)) => (user, Some(domain)),
        None => (no_upn, None),
    };
    let domain = netbios_domain
        .or(upn_domain)
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .unwrap_or(default_domain);
    (domain.to_string(), bare.trim().to_string())
}

/// SharpHound-style reachability pre-check: is `host:445` accepting TCP within
/// `port_timeout_ms`? Run before any SMB work so a dead host is skipped quickly
/// instead of eating the full connect budget. Shared by the sessions,
/// local-group and webclient modules.
pub async fn is_reachable(host: &str, port_timeout_ms: u64) -> bool {
    let target = format!("{host}:445");
    trace!("[{host}] is_reachable: begin, target={target}, budget={port_timeout_ms}ms");
    trace!("[{host}] is_reachable: >>> TcpStream::connect({target}) (name resolution happens here)");
    let outcome = timeout(
        Duration::from_millis(port_timeout_ms),
        TcpStream::connect(target),
    )
    .await;
    let reachable = matches!(outcome, Ok(Ok(_)));
    trace!("[{host}] is_reachable: <<< returned, reachable={reachable}");
    reachable
}

#[cfg(test)]
mod tests {
    use super::smb_identity;

    fn id(raw: &str) -> (String, String) {
        smb_identity(raw, "EXAMPLE.LOCAL")
    }

    #[test]
    fn upn_signs_in_to_its_own_domain() {
        assert_eq!(id("alice@child.example.local"), ("child.example.local".into(), "alice".into()));
    }

    #[test]
    fn down_level_name_signs_in_to_its_own_domain() {
        assert_eq!(id("CHILD\\alice"), ("CHILD".into(), "alice".into()));
    }

    #[test]
    fn bare_name_falls_back_to_default_domain() {
        assert_eq!(id("alice"), ("EXAMPLE.LOCAL".into(), "alice".into()));
        assert_eq!(id("  alice  "), ("EXAMPLE.LOCAL".into(), "alice".into()));
    }

    #[test]
    fn empty_domain_part_falls_back_to_default_domain() {
        assert_eq!(id("alice@"), ("EXAMPLE.LOCAL".into(), "alice".into()));
        assert_eq!(id("\\alice"), ("EXAMPLE.LOCAL".into(), "alice".into()));
    }

    #[test]
    fn down_level_domain_wins_over_upn_suffix() {
        assert_eq!(id("CHILD\\alice@example.local"), ("CHILD".into(), "alice".into()));
    }

    #[test]
    fn upn_splits_at_the_last_at_sign() {
        assert_eq!(id("a@b@child.example.local"), ("child.example.local".into(), "a@b".into()));
    }

    #[test]
    fn spaces_around_the_parts_are_dropped() {
        assert_eq!(id("CHILD\\ alice"), ("CHILD".into(), "alice".into()));
        assert_eq!(id("alice @ child.example.local"), ("child.example.local".into(), "alice".into()));
    }

    #[test]
    fn missing_user_part_gives_an_empty_user() {
        assert_eq!(id("CHILD\\"), ("CHILD".into(), String::new()));
        assert_eq!(id("@child.example.local"), ("child.example.local".into(), String::new()));
    }

    #[test]
    fn empty_username_keeps_default_domain() {
        assert_eq!(id(""), ("EXAMPLE.LOCAL".into(), String::new()));
    }
}
