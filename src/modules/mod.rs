//! List of RustHound add-on modules
pub mod gpo;
pub mod resolver;
pub mod sessions;
pub mod adcs;

use std::error::Error;

use rayon::prelude::*;

use crate::api::ADResults;
use crate::args::{CollectionMethod, Options};
use crate::modules::adcs::probe_enterpriseca_esc8;

/// Function to run all modules requested
pub async fn run_modules(
    common_args: &Options,
    ad: &mut ADResults,
) -> Result<(), Box<dyn Error>> {

   // [MODULE - RESOLVER] Resolve FQDN to IP address.
   if common_args.fqdn_resolver {
        resolver::resolv::resolving_all_fqdn(
            common_args.dns_tcp,
            &common_args.name_server,
            &mut ad.mappings.fqdn_ip,
            &ad.computers,
        ).await;
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
      log::info!("Starting ESC8 web enrollment probe on {} CA(s)...", ad.enterprisecas.len());
      ad.enterprisecas.par_iter_mut().for_each(|ca| {
         let esc8 = probe_enterpriseca_esc8(ca.dns_host());
         ca.apply_esc8(esc8.http_enrollment_endpoints);
      });
   }

    // [MODULE - GPO SYSVOL] read GptTmpl.inf / Groups.xml off the DC SYSVOL share.
    // <#47 Privileges> and <#56 LocalGroup>. DC-side I/O, so it also runs in DCOnly.
    if common_args.collection_method.does_gpo() {
      let sysvol = match collect_sysvol_targets(common_args).await {
         Ok(v) => v,
         Err(e) => {
            log::warn!("[gpo] SYSVOL collection failed: {e}");
            Vec::new()
         }
      };
      if !sysvol.is_empty() {
         log::info!("[gpo] mapping {} GPO(s) to GPOChanges / UserRights", sysvol.len());
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

/// Build the SMB target and credentials, then collect GPO directives off SYSVOL.
async fn collect_sysvol_targets(common_args: &Options) -> anyhow::Result<Vec<gpo::SysvolGpo>> {
    use crate::transport::smb::{nt_hash_from_str, SmbAuth};

    let user = common_args.username.clone().unwrap_or_default();
    let password = common_args.password.clone().unwrap_or_default();
    let nt = common_args.hashes.as_deref().and_then(nt_hash_from_str);
    let auth = match &nt {
        Some(h) => SmbAuth::Hash(h),
        None => SmbAuth::Password(&password),
    };

    // SMB target: explicit IP first, then the DC FQDN, then the domain value.
   let dc_host = common_args
      .ip
      .as_deref()
      .filter(|s| !s.is_empty())
      .or(common_args.ldapfqdn.as_deref())
      .map(str::to_string)
      .unwrap_or_else(|| common_args.domain.clone());

    if dc_host.is_empty() {
        log::warn!("[gpo] no SMB target (ip/ldapfqdn/domain) available, skipping SYSVOL collection");
        return Ok(Vec::new());
    }

    // domain_fqdn (SYSVOL sub-root) = the domain DNS name.
    gpo::collect_sysvol(&dc_host, &common_args.domain, &common_args.domain, &user, auth).await
}