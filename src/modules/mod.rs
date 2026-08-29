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

   // Other modules need to be add here...
   Ok(())
}