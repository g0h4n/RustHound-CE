//! Run a LDAP enumeration and parse results
//!
//! This module will prepare your connection and request the LDAP server to retrieve all the information needed to create the json files.
//!
//! rusthound sends only one request to the LDAP server, if the result of this one is higher than the limit of the LDAP server limit it will be split in several requests to avoid having an error 4 (LDAP_SIZELIMIT_EXCEED).
//!
//! Example in rust
//!
//! ```ignore
//! let search = ldap_search(...)
//! ```

use crate::args::LdapAuth;
// use crate::errors::Result;
use crate::banner::progress_bar;
use crate::storage::Storage;
use crate::utils::format::domain_to_dc;

use colored::Colorize;
use indicatif::ProgressBar;
use ldap3::adapters::{Adapter, EntriesOnly};
use ldap3::{adapters::PagedResults, controls::RawControl, LdapConnAsync, LdapConnSettings};
use ldap3::{Scope, SearchEntry};
use log::{info, debug, error, trace};
use std::io::{self, Write, stdin};
use std::collections::HashMap;
use std::error::Error;
use std::process;

/// Function to request all AD values.
#[allow(clippy::too_many_arguments)]
pub async fn ldap_search<S: Storage<LdapSearchEntry>>(
    ldaps: bool,
    ip: Option<&str>,
    port: Option<u16>,
    domain: &str,
    ldapfqdn: &str,
    username: Option<&str>,
    // password: Option<&str>,
    auth: Option<&crate::args::LdapAuth>,
    kerberos: bool,
    ldapfilter: &str,
    storage: &mut S,
) -> Result<usize, Box<dyn Error>> {
    // Construct LDAP args
    let ldap_args = ldap_constructor(
        ldaps, ip, port, domain, ldapfqdn, username, auth, kerberos,
    )?;



    // LDAP connection
    let consettings = LdapConnSettings::new()
        .set_conn_timeout(std::time::Duration::from_secs(10))
        .set_no_tls_verify(true);
    let (conn, mut ldap) = LdapConnAsync::with_settings(consettings, &ldap_args.s_url).await?;
    ldap3::drive!(conn);

    if !kerberos {
        debug!("Trying to connect with simple_bind() function (username:password)");
        let res = match ldap_args.s_auth {
            LdapAuth::Password(ref password) => ldap.simple_bind(&ldap_args.s_username, password).await?.success(),
            LdapAuth::Ntlm(ref ntlm_hash) => {
                // TODO: refactor `sasl_ntlmv2_bind_with_hash` to handle username@domain
                // or refactor `ldap_constructor`
                let (username, domain) = ldap_args._s_email.split_once('@').unwrap_or((&ldap_args.s_username, "not set"));

                ldap.sasl_ntlmv2_bind_with_hash(username, domain, ntlm_hash.as_bytes()).await?.success()
            },
        };
        match res {
            Ok(_res) => {
                info!(
                    "Connected to {} Active Directory!",
                    domain.to_uppercase().bold().green()
                );
                info!("Starting data collection...");
            }
            Err(err) => {
                error!(
                    "Failed to authenticate to {} Active Directory. Reason: {err}\n",
                    domain.to_uppercase().bold().red()
                );
                process::exit(0x0100);
            }
        }
    } else {
        debug!("Trying to connect with sasl_gssapi_bind() function (kerberos session)");
        if !&ldapfqdn.contains("not set") {
            #[cfg(not(feature = "nogssapi"))]
            gssapi_connection(&mut ldap, &ldapfqdn, &domain).await?;
            #[cfg(feature = "nogssapi")]
            {
                error!("Kerberos auth and GSSAPI not compatible with current os!");
                process::exit(0x0100);
            }
        } else {
            error!(
                "Need Domain Controller FQDN to bind GSSAPI connection. Please use '{}'\n",
                "-f DC01.DOMAIN.LAB".bold()
            );
            process::exit(0x0100);
        }
    }

    // // Prepare LDAP result vector
    let mut total = 0; // for progress bar

    // Request all namingContexts for current DC
    let res = match get_all_naming_contexts(&mut ldap).await {
        Ok(res) => {
            trace!("naming_contexts: {:?}", &res);
            res
        }
        Err(err) => {
            error!("No namingContexts found! Reason: {err}\n");
            process::exit(0x0100);
        }
    };

    // namingContexts: DC=domain,DC=local
    // namingContexts: CN=Configuration,DC=domain,DC=local (needed for AD CS datas)
    if res.iter().any(|s| s.contains("Configuration")) {
        for cn in &res {
            // Set control LDAP_SERVER_SD_FLAGS_OID to get nTSecurityDescriptor
            // https://ldapwiki.com/wiki/LDAP_SERVER_SD_FLAGS_OID
            let ctrls = RawControl {
                ctype: String::from("1.2.840.113556.1.4.801"),
                crit: true,
                val: Some(vec![48, 3, 2, 1, 5]),
            };
            ldap.with_controls(ctrls.to_owned());

            // Prepare filter
            // let mut _s_filter: &str = "";
            // if cn.contains("Configuration") {
            //     _s_filter = "(|(objectclass=pKIEnrollmentService)(objectclass=pkicertificatetemplate)(objectclass=subschema)(objectclass=certificationAuthority)(objectclass=container))";
            // } else {
            //     _s_filter = "(objectClass=*)";
            // }
            //let _s_filter = "(objectClass=*)";
            //let _s_filter = "(objectGuid=*)";
            info!("Ldap filter : {}", ldapfilter.bold().green());
            let _s_filter = ldapfilter;

            // Every 999 max value in ldap response (err 4 ldap)
            let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
                Box::new(EntriesOnly::new()),
                Box::new(PagedResults::new(999)),
            ];

            // Streaming search with adaptaters and filters
            let mut search = ldap
                .streaming_search_with(
                    adapters, // Adapter which fetches Search results with a Paged Results control.
                    cn,
                    Scope::Subtree,
                    _s_filter,
                    vec!["*", "nTSecurityDescriptor"],
                    // Without the presence of this control, the server returns an SD only when the SD attribute name is explicitly mentioned in the requested attribute list.
                    // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/932a7a8d-8c93-4448-8093-c79b7d9ba499
                )
                .await?;

            // Wait and get next values
            let pb = ProgressBar::new(1);
            let mut count = 0;
            while let Some(entry) = search.next().await? {
                let entry = SearchEntry::construct(entry);
                //trace!("{:?}", &entry);
                total += 1;
                // Manage progress bar
                count += 1;
                progress_bar(
                    pb.to_owned(),
                    "LDAP objects retrieved".to_string(),
                    count,
                    "#".to_string(),
                );

                storage.add(entry.into())?;
            }
            pb.finish_and_clear();

            let res = search.finish().await.success();
            match res {
                Ok(_res) => info!("All data collected for NamingContext {}", &cn.bold()),
                Err(err) => {
                    error!("No data collected on {}! Reason: {err}", &cn.bold().red());
                }
            }
        }
        // // If no result exit program
        // if rs.is_empty() {
        //     process::exit(0x0100);
        // }

        ldap.unbind().await?;
    }

    // drop ldap before final flush,
    // otherwise it will warn about an i/o error
    // "LDAP connection error: I/O error: Connection reset by peer (os error 54)"
    drop(ldap);
    if total == 0 {
        error!("No LDAP objects found! Exiting...");
        // std::fs::remove_file(cache_path)?; // TODO: return error so we can cleanup cache
        process::exit(0x0100);
    }

    storage.flush()?;


    // Return the vector with the result
    Ok(total)
}

/// Structure containing the LDAP connection arguments.
struct LdapArgs {
    s_url: String,
    _s_dc: Vec<String>,
    _s_email: String,
    s_username: String,
    // s_password: String,
    s_auth: crate::args::LdapAuth,
}

/// Function to prepare LDAP arguments.
fn ldap_constructor(
    ldaps: bool,
    ip: Option<&str>,
    port: Option<u16>,
    domain: &str,
    ldapfqdn: &str,
    username: Option<&str>,
    // password: Option<&str>,
    auth: Option<&crate::args::LdapAuth>,
    kerberos: bool,
) -> Result<LdapArgs, Box<dyn Error>> {
    // Prepare ldap url
    let s_url = prepare_ldap_url(ldaps, ip, port, domain);

    // Prepare full DC chain
    let s_dc = prepare_ldap_dc(domain);

    // Username prompt
    let mut s = String::new();
    let mut _s_username: String;
    if username.is_none() && !kerberos {
        print!("Username: ");
        io::stdout().flush()?;
        stdin()
            .read_line(&mut s)
            .expect("Did not enter a correct username");
        io::stdout().flush()?;
        if let Some('\n') = s.chars().next_back() {
            s.pop();
        }
        if let Some('\r') = s.chars().next_back() {
            s.pop();
        }
        _s_username = s.to_owned();
    } else {
        _s_username = username.unwrap_or("not set").to_owned();
    }

    // Format username and email
    let mut s_email: String = "".to_owned();
    if !_s_username.contains("@") {
        s_email.push_str(&_s_username.to_string());
        s_email.push('@');
        s_email.push_str(domain);
        _s_username = s_email.to_string();
    } else {
        s_email = _s_username.to_string().to_lowercase();
    }

    // Password prompt
    // let mut _s_password: String = String::new();
    // if !_s_username.contains("not set") && !kerberos {
    //     _s_password = match password {
    //         Some(p) => p.to_owned(),
    //         None => rpassword::prompt_password("Password: ").unwrap_or("not set".to_string()),
    //     };
    // } else {
    //     _s_password = password.unwrap_or("not set").to_owned();
    // }
    let mut _s_auth = LdapAuth::Password("not set".to_string());

    if !_s_username.contains("not set") && !kerberos {
        _s_auth = match auth {
            Some(LdapAuth::Password(p)) => LdapAuth::Password(p.to_owned()),
            Some(LdapAuth::Ntlm(h)) => LdapAuth::Ntlm(h.to_owned()),
            None => LdapAuth::Password(rpassword::prompt_password("Password: ").unwrap_or("not set".to_string())),
        };
    } else {
        _s_auth = auth.unwrap_or(&LdapAuth::Password("not set".to_string())).to_owned();
    }


    // Print infos if verbose mod is set
    debug!("IP: {}", ip.unwrap_or("not set"));
    debug!("PORT: {}", match port {
        Some(p) => {
            p.to_string()
        },
        None => "not set".to_owned()
    });
    debug!("FQDN: {}", ldapfqdn);
    debug!("Url: {}", s_url);
    debug!("Domain: {}", domain);
    debug!("Username: {}", _s_username);
    debug!("Email: {}", s_email.to_lowercase());
    debug!("Password: {:?}", _s_auth);
    debug!("DC: {:?}", s_dc);
    debug!("Kerberos: {:?}", kerberos);

    Ok(LdapArgs {
        s_url: s_url.to_string(),
        _s_dc: s_dc,
        _s_email: s_email.to_string().to_lowercase(),
        s_username: s_email.to_string().to_lowercase(),
        // s_password: _s_password.to_string(),
        s_auth: _s_auth,
    })
}

/// Function to prepare LDAP url.
fn prepare_ldap_url(
    ldaps: bool,
    ip: Option<&str>,
    port: Option<u16>,
    domain: &str
) -> String {
    let protocol = if ldaps || port.unwrap_or(0) == 636 {
        "ldaps"
    } else {
        "ldap"
    };

    let target = match ip {
        Some(ip) => ip,
        None => domain,
    };

    match port {
        Some(port) => {
            format!("{protocol}://{target}:{port}")
        }
        None => {
            format!("{protocol}://{target}")
        }
    }
}

/// Function to prepare LDAP DC from DOMAIN.LOCAL
pub fn prepare_ldap_dc(domain: &str) -> Vec<String> {

    let mut dc: String = "".to_owned();
    let mut naming_context: Vec<String> = Vec::new();

    // Format DC
    if !domain.contains(".") {
        dc.push_str("DC=");
        dc.push_str(domain);
        naming_context.push(dc[..].to_string());
    }
    else {
        naming_context.push(domain_to_dc(domain));
    }

    // For ADCS values
    naming_context.push(format!("{}{}", "CN=Configuration,", &dc[..])); 
    naming_context
}

/// Function to make GSSAPI ldap connection.
#[cfg(not(feature = "nogssapi"))]
async fn gssapi_connection(
    ldap: &mut ldap3::Ldap,
    ldapfqdn: &str,
    domain: &str,
) -> Result<(), Box<dyn Error>> {
    let res = ldap.sasl_gssapi_bind(ldapfqdn).await?.success();
    match res {
        Ok(_res) => {
            info!("Connected to {} Active Directory!", domain.to_uppercase().bold().green());
            info!("Starting data collection...");
        }
        Err(err) => {
            error!("Failed to authenticate to {} Active Directory. Reason: {err}\n", domain.to_uppercase().bold().red());
            process::exit(0x0100);
        }
    }
    Ok(())
}

/// (Not needed yet) Get all namingContext for DC
pub async fn get_all_naming_contexts(
    ldap: &mut ldap3::Ldap
) -> Result<Vec<String>, Box<dyn Error>> {
    // Every 999 max value in ldap response (err 4 ldap)
    let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResults::new(999)),
    ];

    // First LDAP request to get all namingContext
    let mut search = ldap.streaming_search_with(
        adapters,
        "", 
        Scope::Base,
        "(objectClass=*)",
        vec!["namingContexts"],
    ).await?;

    // Prepare LDAP result vector
    let mut rs: Vec<SearchEntry> = Vec::new();
    while let Some(entry) = search.next().await? {
        let entry = SearchEntry::construct(entry);
        rs.push(entry);
    }
    let res = search.finish().await.success();

    // Prepare vector for all namingContexts result
    let mut naming_contexts: Vec<String> = Vec::new();
    match res {
        Ok(_res) => {
            debug!("All namingContexts collected!");
            for result in rs {
                let result_attrs: HashMap<String, Vec<String>> = result.attrs;

                for (_key, value) in &result_attrs {
                    for naming_context in value {
                        debug!("namingContext found: {}",&naming_context.bold().green());
                        naming_contexts.push(naming_context.to_string());
                    }
                }
            }
            return Ok(naming_contexts)
        }
        Err(err) => {
            error!("No namingContexts found! Reason: {err}");
        }
    }
    // Empty result if no namingContexts found
    Ok(Vec::new())
}

// New type to implement Serialize and Deserialize for SearchEntry
#[derive(Debug, Clone, bincode::Encode, bincode::Decode)]
pub struct LdapSearchEntry {
    /// Entry DN.
    pub dn: String,
    /// Attributes.
    pub attrs: HashMap<String, Vec<String>>,
    /// Binary-valued attributes.
    pub bin_attrs: HashMap<String, Vec<Vec<u8>>>,
}

impl From<SearchEntry> for LdapSearchEntry {
    fn from(entry: SearchEntry) -> Self {
        LdapSearchEntry {
            dn: entry.dn,
            attrs: entry.attrs,
            bin_attrs: entry.bin_attrs,
        }
    }
}

impl From<LdapSearchEntry> for SearchEntry {
    fn from(entry: LdapSearchEntry) -> Self {
        SearchEntry {
            dn: entry.dn,
            attrs: entry.attrs,
            bin_attrs: entry.bin_attrs,
        }
    }
}
