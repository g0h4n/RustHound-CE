//! Remote registry collection over MS-RRP (`\PIPE\winreg`) for RustHound-CE
//! (issue #97). This module will also host the DC and NTLM registry collectors;
//! today it collects the CA-registry values in `CARegistryData`.
//!
//! Runs AFTER the LDAP phase, from `modules::run_modules`, under the `All` and
//! `CARegistry` collection methods (like LocalGroup / WebClient, NOT under
//! RegistryOnly). For each Enterprise CA it reads two HKLM values the LDAP
//! object cannot carry and folds them into `CARegistryData`:
//!
//!   EditFlags (policy module)      -> IsUserSpecifiesSanEnabled  (ESC6a; ESC6b also needs DCRegistryData)
//!   RoleSeparationEnabled (config) -> RoleSeparationEnabled       (informational; no BloodHound edge today)
//!
//! Modelled on SharpHoundCommon v4.9.0 `CertAbuseProcessor`, including its
//! not-set rule (see [`types`]). The reader lives in [`careg`]; the
//! Domain-Controller-free logic and its unit tests live in [`types`].
//! `run_modules` gates this module behind `!cert_auth`, as it does the other
//! SMB-based modules. dcerpc's `RegistryClient` binds with a password or an
//! NT hash only (no Kerberos bind yet); a run with neither records the
//! values as not collected.

pub mod careg;
pub mod types;

use std::error::Error;
use std::sync::Arc;

use futures::future;
use log::{debug, info, trace, warn};
use tokio::sync::Semaphore;

use crate::args::Options;
use crate::objects::enterpriseca::EnterpriseCA;
use crate::transport::smb::{nt_hash_from_str, smb_identity};

const DEFAULT_CONCURRENCY: usize = 10; // bounded parallel CAs (~ SharpHound --Throttle), as session/webclient
const DEFAULT_PORT_TIMEOUT_MS: u64 = 1_500; // 445 reachability pre-check budget, as session/webclient
const DEFAULT_PER_CA_TIMEOUT_MS: u64 = 30_000; // whole per-CA budget; larger than the sibling modules' per-host probe timeout because it also covers the sealed MS-RRP round-trips plus the one Remote Registry retry
const WINREG_RETRY_DELAY_MS: u64 = 3_000; // STATUS_PIPE_NOT_AVAILABLE (0xc00000ac): Remote Registry is trigger-starting; wait then retry once

/// Entry point called by `run_modules`.
pub async fn run(args: &Options, cas: &mut [EnterpriseCA]) -> Result<(), Box<dyn Error>> {
    // Hard guard: only the method(s) that collect the CA registry reach a host.
    if !args.collection_method.does_ca_registry() {
        debug!("[careg] collection method does not collect CA registry - skipping");
        return Ok(());
    }
    if cas.is_empty() {
        return Ok(());
    }

    // SMB sign-in identity: the account's own domain from -u, else --domain.
    // Password / pass-the-hash only: dcerpc's RegistryClient has no Kerberos bind yet.
    let (signin_domain, user) =
        smb_identity(args.username.as_deref().unwrap_or_default(), &args.domain);
    let password = args.password.clone().unwrap_or_default();
    let nt_hash = nt_hash_from_str(args.hashes.as_deref().unwrap_or_default());

    // Targets in CA order (so the results fold straight back by position), with
    // the empty-dnshostname CAs dropped: there is nothing to connect to.
    let targets: Vec<(usize, String, String)> = cas
        .iter()
        .enumerate()
        .filter(|(_, ca)| !ca.dns_host().is_empty())
        .map(|(i, ca)| (i, ca.dns_host().to_string(), ca.caname().to_string()))
        .collect();

    if targets.is_empty() {
        return Ok(());
    }

    // dcerpc's RegistryClient binds with a password or NT hash only (no
    // Kerberos bind yet). With neither (e.g. -k without -p/-H), don't attempt a doomed
    // bind against every CA: record the read as not collected, with the
    // reason, so BloodHound sees Collected:false rather than a false default.
    if password.is_empty() && nt_hash.is_none() {
        let reason =
            "not collected: the MS-RRP bind needs a password or NT hash (dcerpc's RegistryClient has no Kerberos bind yet)"
                .to_string();
        info!(
            "[careg] no password or NT hash available - not reading CA registry on {} CA(s)",
            targets.len()
        );
        for (idx, _, _) in &targets {
            cas[*idx].set_user_specifies_san(false, Some(reason.clone()));
            cas[*idx].set_role_separation(false, Some(reason.clone()));
        }
        return Ok(());
    }

    info!(
        "[careg] reading CA registry over MS-RRP on {} of {} CA(s)",
        targets.len(),
        cas.len()
    );

    // Read with bounded concurrency; order is preserved by join_all.
    let sem = Arc::new(Semaphore::new(DEFAULT_CONCURRENCY));
    let reads = future::join_all(targets.into_iter().map(|(idx, host, ca_name)| {
        let (sem, signin_domain, user, password) =
            (sem.clone(), signin_domain.clone(), user.clone(), password.clone());
        async move {
            let _permit = sem.acquire().await.unwrap();
            trace!("[careg] [{host}] permit acquired, reading CA '{ca_name}'");
            let reads =
                careg::collect(&host, &signin_domain, &user, &password, nt_hash.as_ref(), &ca_name)
                    .await;
            (idx, reads)
        }
    }))
    .await;

    // Fold each CA's reads back onto its EnterpriseCA via the mutators. The
    // count is of EditFlags reads: that is the value BloodHound's edges use.
    let mut collected = 0usize;
    for (idx, read) in reads {
        let (san_value, san_failure) = types::user_specifies_san_outcome(&read.user_specifies_san);
        let (role_value, role_failure) = types::role_separation_outcome(&read.role_separation);
        let ca_name = cas[idx].caname().to_string();
        match &san_failure {
            None => collected += 1,
            Some(reason) => warn!("[careg] {ca_name}: {} not collected: {reason}", types::EDIT_FLAGS),
        }
        if let Some(reason) = &role_failure {
            debug!(
                "[careg] {ca_name}: {} not collected: {reason}",
                types::ROLE_SEPARATION_ENABLED
            );
        }
        let ca = &mut cas[idx];
        ca.set_user_specifies_san(san_value, san_failure);
        ca.set_role_separation(role_value, role_failure);
    }

    info!("[careg] EditFlags collected on {collected} CA(s)");
    Ok(())
}
