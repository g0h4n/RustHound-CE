//! List of RustHound add-on modules
pub mod adcs;
pub mod gpo;
pub mod resolver;
pub mod sessions;

use std::error::Error;

use futures::future;

use crate::api::ADResults;
use crate::args::{CollectionMethod, Options};
use crate::modules::adcs::probe_enterpriseca_esc8;
use crate::modules::gpo::sysvol::collect_sysvol_targets;

/// Function to run all modules requested
pub async fn run_modules(
    common_args: &Options,
    ad: &mut ADResults
) -> Result<(), Box<dyn Error>> {

    let cert_auth = common_args.uses_cert();
    if cert_auth {
        log::warn!("Certificate authentication in use: skipping SMB-based modules \
                    (sessions and GPO/SYSVOL) no SMB credentials available.");
    }

    // [MODULE - RESOLVER] Resolve FQDN to IP address.
    if common_args.fqdn_resolver {
        resolver::resolv::resolving_all_fqdn(
            common_args.dns_tcp,
            &common_args.name_server,
            &mut ad.mappings.fqdn_ip,
            &ad.computers,
        )
        .await;
    }

    // [MODULE - SESSIONS] Just does user session collection
    // <https://github.com/g0h4n/HasSession-rs>
    //
    // - SRVSVC / NetrSessionEnum - inbound SMB sessions (client IP + username).
    // - WKSSVC / NetrWkstaUserEnum - users with an active logon context on the machine.
    // - WINREG / HKEY_USERS - SIDs of loaded profile hives (= logged-on users).
    if common_args.collection_method.does_sessions() && !cert_auth {
        sessions::run(common_args, &ad.users, &mut ad.computers).await?;
    }

    // [MODULE - ESC8] Web enrollment probe on all enterprise CAs.
    // Skipped in DCOnly mode (no direct machine connections allowed).
    // Each probe's blocking reqwest client runs via tokio::task::spawn_blocking
    // on Tokio's dedicated blocking thread pool. Building/dropping a
    // reqwest::blocking::Client (which owns its own nested Tokio runtime)
    // panics on drop if done on a thread already inside an async context; the
    // previous rayon par_iter_mut could run the closure on the calling Tokio
    // worker thread itself (e.g. with a single CA), which was the crash.
    if !matches!(common_args.collection_method, CollectionMethod::DCOnly)
        && !matches!(common_args.collection_method, CollectionMethod::LdapOnly)
        && !ad.enterprisecas.is_empty()
    {
        log::info!(
            "Starting ESC8 web enrollment probe on {} CA(s)...",
            ad.enterprisecas.len()
        );
        let hosts: Vec<String> = ad
            .enterprisecas
            .iter()
            .map(|ca| ca.dns_host().to_string())
            .collect();
        let probes = future::join_all(hosts.into_iter().map(|host| {
            tokio::task::spawn_blocking(move || probe_enterpriseca_esc8(&host))
        }))
        .await;
        for (ca, probe) in ad.enterprisecas.iter_mut().zip(probes) {
            match probe {
                Ok(esc8) => ca.apply_esc8(esc8.http_enrollment_endpoints),
                Err(join_err) => log::warn!(
                    "[adcs] ESC8 probe task for {} did not complete ({}), skipping",
                    ca.dns_host(),
                    join_err
                ),
            }
        }
    }

    // [MODULE - GPO SYSVOL] read GptTmpl.inf / Groups.xml off the DC SYSVOL share.
    // <#47 Privileges> and <#56 LocalGroup>. DC-side I/O, so it also runs in DCOnly.
    if common_args.collection_method.does_gpo() && !cert_auth {
        let computer_scope = gpo::sysvol::ComputerGpoScope::from_gpos(&ad.gpos);
        let sysvol = match collect_sysvol_targets(common_args, &computer_scope).await {
            Ok(v) => v,
            Err(e) => {
                log::warn!("[gpo] SYSVOL collection failed: {e}");
                Vec::new()
            }
        };
        if !sysvol.is_empty() {
            log::info!(
                "[gpo] mapping {} GPO(s) to GPOChanges / UserRights",
                sysvol.len()
            );
            gpo::apply_gpo(
                &mut ad.ous,
                &mut ad.domains,
                &ad.users,
                &ad.groups,
                &mut ad.computers,
                &sysvol,
                &ad.mappings.dn_sid,
            );
        }
    }

    // Other modules need to be add here...
    Ok(())
}