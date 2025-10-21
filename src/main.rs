pub mod banner;
pub mod modules;

use env_logger::Builder;
use log::{error, info, trace};

use rusthound_ce::{
    args, ldap, objects,
    DiskStorage, DiskStorageReader,
    utils,
};

use std::error::Error;
use colored::Colorize;

#[cfg(feature = "noargs")]
use args::auto_args;
#[cfg(not(feature = "noargs"))]
use args::{extract_args, Options};

use banner::{print_banner, print_end_banner};
use ldap::ldap_search;
use modules::run_modules;

const CACHE_DIR: &str = ".rusthound-cache";
const CACHE_FILE: &str = "ldap.bin";

/// Main of RustHound
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Banner
    print_banner();

    // Get args
    #[cfg(not(feature = "noargs"))]
    let common_args: Options = extract_args();
    #[cfg(feature = "noargs")]
    let common_args = auto_args();

    // Build logger
    Builder::new()
        .filter(Some("rusthound"), common_args.verbose)
        .filter_level(log::LevelFilter::Error)
        .init();

    // Get verbose level
    info!("Verbosity level: {:?}", common_args.verbose);
    info!("Collection method: {:?}", common_args.collection_method);

    let mut results = match common_args.resume {
        true => {
            let ldap_cache_path = std::path::PathBuf::from(CACHE_DIR)
                .join(&common_args.domain)
                .join(CACHE_FILE);
            info!("Resuming from cache: {}", format!("{}",ldap_cache_path.display()).bold());
            let cache = DiskStorageReader::from_path(ldap_cache_path)?;
            rusthound_ce::prepare_results_from_source(cache, &common_args, None).await?
        }
        false => {
            if common_args.cache {
                // store ldap results in cache
                let ldap_cache_path = std::path::PathBuf::from(CACHE_DIR)
                    .join(&common_args.domain)
                    .join(CACHE_FILE);
                std::fs::create_dir_all(
                    ldap_cache_path
                        .parent()
                        .expect("Unable to get parent directory for cache path"), // shouldn't happen
                )?;
                info!("Using cache for LDAP search: {}", format!("{}",ldap_cache_path.display()).bold());

                let mut cache_writer = DiskStorage::new_with_capacity(
                    ldap_cache_path,
                    common_args.cache_buffer_size,
                )?;

                let total_cached = ldap_search(
                    common_args.ldaps,
                    common_args.ip.as_deref(),
                    common_args.port,
                    &common_args.domain,
                    &common_args.ldapfqdn,
                    common_args.username.as_deref(),
                    common_args.auth.as_ref(),
                    common_args.kerberos,
                    &common_args.ldap_filter,
                    &mut cache_writer,
                )
                .await?;

                rusthound_ce::prepare_results_from_source(
                    cache_writer.into_reader()?,
                    &common_args,
                    Some(total_cached),
                )
                .await?
            } else {
                // store ldap results in memory
                let mut ldap_results = Vec::new();
                let total = rusthound_ce::ldap::ldap_search(
                    common_args.ldaps,
                    common_args.ip.as_deref(),
                    common_args.port,
                    &common_args.domain,
                    &common_args.ldapfqdn,
                    common_args.username.as_deref(),
                    common_args.auth.as_ref(),
                    common_args.kerberos,
                    &common_args.ldap_filter,
                    &mut ldap_results,
                )
                .await?;
                rusthound_ce::prepare_results_from_source(ldap_results, &common_args, Some(total))
                    .await?
            }
        }
    };

    // Running modules
    run_modules(
        &common_args,
        &mut results.mappings.fqdn_ip,
        &mut results.computers,
    )
    .await?;

    // Add all in json files
    match rusthound_ce::make_result(&common_args, results) {
        Ok(_) => trace!("Making json/zip files finished!"),
        Err(err) => error!("Error. Reason: {err}"),
    }

    // End banner
    print_end_banner();
    Ok(())
}
