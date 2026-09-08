//! List of RustHound add-on modules
pub mod adcs;
pub mod gpo;
pub mod resolver;
pub mod sessions;

use std::error::Error;

use rayon::prelude::*;

use crate::api::ADResults;
use crate::args::{CollectionMethod, Options};
use crate::modules::adcs::probe_enterpriseca_esc8;
use crate::modules::gpo::sysvol::collect_sysvol_targets;

/// Function to run all modules requested
pub async fn run_modules(common_args: &Options, ad: &mut ADResults) -> Result<(), Box<dyn Error>> {
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
    if common_args.collection_method.does_sessions() {
        sessions::run(common_args, &ad.users, &mut ad.computers).await?;
    }

    // [MODULE - ESC8] Web enrollment probe on all enterprise CAs.
    // Skipped in DCOnly mode (no direct machine connections allowed).
    // Uses rayon to probe all CAs in parallel (each probe has a 5 s timeout).
    if !matches!(common_args.collection_method, CollectionMethod::DCOnly)
        && !matches!(common_args.collection_method, CollectionMethod::LdapOnly)
        && !ad.enterprisecas.is_empty()
    {
        log::info!(
            "Starting ESC8 web enrollment probe on {} CA(s)...",
            ad.enterprisecas.len()
        );
        ad.enterprisecas.par_iter_mut().for_each(|ca| {
            let esc8 = probe_enterpriseca_esc8(ca.dns_host());
            ca.apply_esc8(esc8.http_enrollment_endpoints);
        });
    }

    // [MODULE - GPO SYSVOL] read GptTmpl.inf / Groups.xml off the DC SYSVOL share.
    // <#47 Privileges> and <#56 LocalGroup>. DC-side I/O, so it also runs in DCOnly.
    if common_args.collection_method.does_gpo() {
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