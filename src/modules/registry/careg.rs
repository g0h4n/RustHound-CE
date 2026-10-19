//! CA-registry reader over MS-RRP (`\PIPE\winreg`) for issue #97.
//!
//! Per Enterprise CA this opens IPC$, binds the Remote Registry interface
//! (sign+seal), and reads two HKLM values:
//!
//!   EditFlags (policy module)      -> IsUserSpecifiesSanEnabled  (ESC6a; ESC6b also needs DCRegistryData)
//!   RoleSeparationEnabled (config) -> RoleSeparationEnabled       (informational; no BloodHound edge today)
//!
//! dcerpc's `RegistryClient` binds with a password or an
//! NT hash only (it has no Kerberos bind yet), reusing the same SMB transport
//! as the sessions module.
//!
//! All decisions that can be made without a Domain Controller live in
//! [`super::types`]; this file only turns a live read into a [`types::ValueRead`].

use log::{debug, trace};
use tokio::time::{sleep, timeout, Duration};

use dcerpc::rrp::RegistryClient;
use smb2_client::SmbClient;

use crate::modules::registry::types::{self, ValueRead};
use crate::transport::smb::{connect_ipc, is_reachable, SmbAuth};

/// The two per-CA value reads, as pure [`ValueRead`]s ready for the outcome
/// mapping in [`super::types`].
pub struct CaReads {
    pub user_specifies_san: ValueRead,
    pub role_separation: ValueRead,
}

impl CaReads {
    /// Both values failed for the same reason (unreachable, connect/auth
    /// failure, or the per-CA timeout).
    fn both_failed(reason: String) -> Self {
        CaReads {
            user_specifies_san: ValueRead::Failed(reason.clone()),
            role_separation: ValueRead::Failed(reason),
        }
    }
}

/// Result of a single `\winreg` open + read attempt, before the retry decision.
enum Attempt {
    /// The bind succeeded; here are the two value reads.
    Read(CaReads),
    /// The `\winreg` open or the sealed bind failed (carries the error text).
    WinregFailed(String),
}

/// Collect the CA-registry values for one CA host: 445 pre-check, then the
/// connect + bind + reads under a whole-CA timeout.
pub async fn collect(
    host: &str,
    domain: &str,
    user: &str,
    password: &str,
    nt_hash: Option<&[u8; 16]>,
    ca_name: &str,
) -> CaReads {
    // SharpHound-style reachability pre-check: 445 open within budget.
    if !is_reachable(host, super::DEFAULT_PORT_TIMEOUT_MS).await {
        trace!("[careg] [{host}] 445/tcp unreachable - skip");
        return CaReads::both_failed(format!("{host}: 445/tcp unreachable"));
    }

    // Whole-CA budget so a slow-but-open host can't stall the run; it is larger
    // than the sibling modules' per-host probe timeout because it also covers
    // the single Remote Registry retry (below) and the sealed MS-RRP round-trips.
    match timeout(
        Duration::from_millis(super::DEFAULT_PER_CA_TIMEOUT_MS),
        connect_and_read(host, domain, user, password, nt_hash, ca_name),
    )
    .await
    {
        Ok(reads) => reads,
        Err(_) => {
            trace!("[careg] [{host}] per-CA timeout");
            CaReads::both_failed(format!("{host}: per-CA timeout"))
        }
    }
}

/// Connect IPC$ (password / pass-the-hash), then read the two values, retrying
/// the `\winreg` bind once if Remote Registry is still trigger-starting.
async fn connect_and_read(
    host: &str,
    domain: &str,
    user: &str,
    password: &str,
    nt_hash: Option<&[u8; 16]>,
    ca_name: &str,
) -> CaReads {
    let auth = match nt_hash {
        Some(h) => SmbAuth::Hash(h),
        None => SmbAuth::Password(password),
    };
    let mut smb = match connect_ipc(host, domain, user, auth).await {
        Ok(c) => c,
        Err(e) => return CaReads::both_failed(format!("{host}: {e}")),
    };
    debug!("[careg] [{host}] IPC$ ready, binding \\winreg for CA '{ca_name}'");

    match open_and_read(&mut smb, domain, user, password, nt_hash, host, ca_name).await {
        Attempt::Read(reads) => reads,
        // Remote Registry is trigger-starting: wait once, then retry the bind.
        Attempt::WinregFailed(e) if types::is_pipe_not_available(&e) => {
            debug!(
                "[careg] [{host}] \\winreg not available yet (0xc00000ac); \
                 retrying once in {}ms",
                super::WINREG_RETRY_DELAY_MS
            );
            sleep(Duration::from_millis(super::WINREG_RETRY_DELAY_MS)).await;
            match open_and_read(&mut smb, domain, user, password, nt_hash, host, ca_name).await {
                Attempt::Read(reads) => reads,
                Attempt::WinregFailed(e2) => CaReads::both_failed(format!("{host}: {e2}")),
            }
        }
        Attempt::WinregFailed(e) => CaReads::both_failed(format!("{host}: {e}")),
    }
}

/// One open+bind of `\winreg` followed by the two value reads. The
/// [`RegistryClient`] borrows `smb` only for the duration of this call, so the
/// caller can reborrow `smb` to retry.
async fn open_and_read(
    smb: &mut SmbClient,
    domain: &str,
    user: &str,
    password: &str,
    nt_hash: Option<&[u8; 16]>,
    host: &str,
    ca_name: &str,
) -> Attempt {
    let mut reg = match connect_registry(smb, domain, user, password, nt_hash, host).await {
        Ok(r) => r,
        Err(e) => return Attempt::WinregFailed(e.to_string()),
    };

    let user_specifies_san = types::classify_read(
        reg.read_value(&types::policy_module_subkey(ca_name), types::EDIT_FLAGS)
            .await,
    );
    let role_separation = types::classify_read(
        reg.read_value(&types::configuration_subkey(ca_name), types::ROLE_SEPARATION_ENABLED)
            .await,
    );

    Attempt::Read(CaReads {
        user_specifies_san,
        role_separation,
    })
}

/// Bind the Remote Registry interface with a password or an NT hash.
async fn connect_registry<'a>(
    smb: &'a mut SmbClient,
    domain: &str,
    user: &str,
    password: &str,
    nt_hash: Option<&[u8; 16]>,
    host: &str,
) -> dcerpc::Result<RegistryClient<'a>> {
    match nt_hash {
        Some(h) => RegistryClient::connect_hash(smb, domain, user, h, host).await,
        None => RegistryClient::connect(smb, domain, user, password, host).await,
    }
}
