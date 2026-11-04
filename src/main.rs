pub mod banner;

// Scalable multithreaded allocator. The default OS allocator (the Windows
// process heap in particular) serializes concurrent allocations behind a lock,
// which throttled every parallel phase — decode, parse, and the checker all
// allocate heavily, so threads spent their time contending instead of working.
// mimalloc uses per-thread heaps and removes that bottleneck.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use env_logger::Builder;
use log::{error, info, trace};

use rusthound_ce::{args, api::run_collection, transport::connect, utils};
use std::error::Error;

#[cfg(feature = "noargs")]
use args::auto_args;
#[cfg(not(feature = "noargs"))]
use args::{extract_args, Options};

use banner::{print_banner, print_end_banner};

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

    info!("Verbosity level: {:?}", common_args.verbose);
    info!("Collection method: {:?}", common_args.collection_method);

    // 1) Resume reads straight from the local cache, so no DC connection is
    //    needed. Otherwise connect + authenticate over the selected transport
    //    (LDAP by default, ADWS/SOAP with --transport soap). The session closes
    //    when `transport` is dropped at the end of the branch.
    let result = if common_args.resume {
        run_collection(None, &common_args).await
    } else {
        let mut transport = connect(&common_args).await?;
        run_collection(Some(transport.as_mut()), &common_args).await
    };

    // 2) Report the outcome of the full workflow (collect -> parse -> modules -> JSON/zip).
    match result {
        Ok(out) => {
            trace!("Output written to {out}");
            // End banner
            print_end_banner();
        },
        Err(err) => error!("Collection failed. Reason: {err}"),
    }

    Ok(())
}