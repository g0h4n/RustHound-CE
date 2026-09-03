//! List of RustHound add-on modules
pub mod gpo;
pub mod resolver;
pub mod sessions;
pub mod adcs;

use std::collections::HashMap;
use std::error::Error;

use rayon::prelude::*;

use crate::args::{CollectionMethod, Options};
use crate::objects::computer::Computer;
use crate::objects::enterpriseca::EnterpriseCA;
use crate::objects::user::User;
use crate::modules::adcs::probe_enterpriseca_esc8;

/// Function to run all modules requested
pub async fn run_modules(
    common_args:        &Options,
    fqdn_ip:            &mut HashMap<String, String>,
    vec_computers:      &mut Vec<Computer>,
    vec_users:          &mut Vec<User>,
    vec_enterprisecas:  &mut Vec<EnterpriseCA>,
) -> Result<(), Box<dyn Error>> {

   // [MODULE - RESOLVER] Running module to resolve FQDN to IP address?
   if common_args.fqdn_resolver {
      resolver::resolv::resolving_all_fqdn(
         common_args.dns_tcp,
         &common_args.name_server,
         fqdn_ip,
         &vec_computers
      ).await;
   }

   // [MODULE - SESSIONS] Just does user session collection 
   // <https://github.com/g0h4n/HasSession-rs>
   //
   // - SRVSVC / NetrSessionEnum - inbound SMB sessions (client IP + username).
   // - WKSSVC / NetrWkstaUserEnum - users with an active logon context on the machine.
   // - WINREG / HKEY_USERS - SIDs of loaded profile hives (= logged-on users).
   if common_args.collection_method.does_sessions() {
      sessions::run(common_args, vec_users, vec_computers).await?;
   }

   // [MODULE - ESC8] Web enrollment probe on all enterprise CAs.
   // Skipped in DCOnly mode (no direct machine connections allowed).
   // Uses rayon to probe all CAs in parallel (each probe has a 5 s timeout).
   if !matches!(common_args.collection_method, CollectionMethod::DCOnly)
        && !vec_enterprisecas.is_empty()
   {
      log::info!(
         "Starting ESC8 web enrollment probe on {} CA(s)...",
         vec_enterprisecas.len()
      );

      vec_enterprisecas.par_iter_mut().for_each(|ca| {
         let esc8 = probe_enterpriseca_esc8(ca.dns_host());
         ca.apply_esc8(esc8.http_enrollment_endpoints);
      });
   }

   // [MODULE - GPO SYSVOL] read GptTmpl.inf / Groups.xml off the DC SYSVOL share
   // <#47 Privileges> and <#56 LocalGroup>. DC-side I/O, so it also runs in DCOnly.
   if common_args.collection_method.does_gpo() {
      use crate::transport::smb::{nt_hash_from_str, SmbAuth};

      let user = common_args.username.clone().unwrap_or_default();
      let password = common_args.password.clone().unwrap_or_default();
      let nt = common_args.hashes.as_deref().and_then(nt_hash_from_str);
      let auth = match &nt {
         Some(h) => SmbAuth::Hash(h),
         None    => SmbAuth::Password(&password),
      };

      // SMB target: prefer an explicit IP, else fall back to the domain value.
      let dc_host = match common_args.ip.as_deref() {
         Some(ip) if !ip.is_empty() => ip.to_string(),
         _ => common_args.domain.clone(),
      };

      if dc_host.is_empty() {
         log::warn!("[gpo] no DC host (ldapfqdn/ip) available, skipping SYSVOL collection");
      } else {
         match gpo::collect_sysvol(&dc_host, &common_args.domain, &common_args.domain, &user, auth).await {
            Ok(gpos) => {
               log::info!("[gpo] {} GPO(s) with directives ready for edge mapping", gpos.len());
               // TODO(edges): map SysvolGpo directives to GPO objects, resolve
               // links to affected computers, emit Privileges / LocalGroup edges.
               let _ = gpos;
            }
            Err(e) => log::warn!("[gpo] SYSVOL collection failed: {e}"),
         }
      }
   }

   // Other modules need to be add here...
   Ok(())
}