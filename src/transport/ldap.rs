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
    password: Option<&str>,
    hashes: Option<&str>,
    kerberos: bool,
    ldapfilter: &str,
    storage: &mut S,
) -> Result<usize, Box<dyn Error>> {
    // Construct LDAP args
    let ldap_args = ldap_constructor(
        ldaps, ip, port, domain, ldapfqdn, username, password, hashes, kerberos,
    )?;

    // LDAP connection
    let consettings = LdapConnSettings::new()
        .set_conn_timeout(std::time::Duration::from_secs(10))
        .set_no_tls_verify(true);
    let (conn, mut ldap) = LdapConnAsync::with_settings(consettings, &ldap_args.s_url).await?;
    ldap3::drive!(conn);

    if let Some(ref ntlm_password) = ldap_args.s_ntlm_password {
        debug!("Trying to connect with sasl_ntlm_bind() function (NTLM pass-the-hash)");
        let res = ldap
            .sasl_ntlm_bind(&ldap_args.s_username, ntlm_password)
            .await?
            .success();
        match res {
            Ok(_res) => {
                info!(
                    "Connected to {} Active Directory via NTLM!",
                    domain.to_uppercase().bold().green()
                );
                info!("Starting data collection...");
            }
            Err(err) => {
                error!(
                    "Failed to authenticate to {} Active Directory via NTLM. Reason: {err}\n",
                    domain.to_uppercase().bold().red()
                );
                process::exit(0x0100);
            }
        }
    } else if !kerberos {
        debug!("Trying to connect with simple_bind() function (username:password)");
        let res = ldap
            .simple_bind(&ldap_args.s_username, &ldap_args.s_password)
            .await?
            .success();
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
            //  Control 1: Set control LDAP_SERVER_SD_FLAGS_OID to get nTSecurityDescriptor
            // https://ldapwiki.com/wiki/LDAP_SERVER_SD_FLAGS_OID
            let sd_flags = RawControl {
                ctype: String::from("1.2.840.113556.1.4.801"),
                crit: true,
                val: Some(vec![48, 3, 2, 1, 5]),    // SEQUENCE { INTEGER 5 }
            };

            // Control 2: LDAP_SERVER_SHOW_DELETED_OID (deleted objects)
            // https://ldapwiki.com/wiki/IsDeleted 
            let show_deleted = RawControl {
                ctype: String::from("1.2.840.113556.1.4.417"),
                crit: false,    // false ignored if not supported
                val: None,
            };

            let controls = vec![sd_flags, show_deleted];
            ldap.with_controls(controls.to_owned());

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
    s_password: String,
    s_ntlm_password: Option<String>,
}

/// Function to prepare LDAP arguments.
fn ldap_constructor(
    ldaps: bool,
    ip: Option<&str>,
    port: Option<u16>,
    domain: &str,
    ldapfqdn: &str,
    username: Option<&str>,
    password: Option<&str>,
    hashes: Option<&str>,
    kerberos: bool,
) -> Result<LdapArgs, Box<dyn Error>> {
    // Prepare ldap url
    let s_url = prepare_ldap_url(ldaps, ip, port, domain);

    // Prepare full DC chain
    let s_dc = prepare_ldap_dc(domain);

    let use_ntlm = hashes.is_some();

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
        s_email.push_str("@");
        s_email.push_str(domain);
        if !use_ntlm {
            _s_username = s_email.to_string();
        }
    } else {
        s_email = _s_username.to_string().to_lowercase();
    }

    // For NTLM, format username as DOMAIN\user for sspi
    if use_ntlm && !_s_username.contains("\\") && !_s_username.contains("@") {
        let domain_upper = domain.split('.').next().unwrap_or(domain).to_uppercase();
        _s_username = format!("{}\\{}", domain_upper, _s_username);
    }

    // Validate and build NTLM password from NT hash if provided
    let s_ntlm_password = match hashes {
        Some(hash) => {
            let clean = hash.trim();
            // Accept [NTHASH, :NTHASH, LMHASH:NTHASH]
            let nt = match clean.split_once(':') {
                Some((_lm, nt)) => nt,
                None => clean,
            };
            if nt.len() != 32 || !nt.chars().all(|c| c.is_ascii_hexdigit()) {
                error!("Invalid NT hash: must be exactly 32 hex characters (e.g. aad3b435b51404eeaad3b435b51404ee)");
                process::exit(0x0100);
            }
            Some(nt_hash_to_ntlm_password(nt))
        }
        None => None,
    };

    // Password prompt (skip when using NTLM hash)
    let mut _s_password: String = String::new();
    if !use_ntlm && !_s_username.contains("not set") && !kerberos {
        _s_password = match password {
            Some(p) => p.to_owned(),
            None => rpassword::prompt_password("Password: ").unwrap_or("not set".to_string()),
        };
    } else {
        _s_password = password.unwrap_or("not set").to_owned();
    }
    
    // Print infos if verbose mod is set
    debug!("IP: {}", match ip {
        Some(ip) => ip,
        None => "not set"
    });
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
    if use_ntlm {
        debug!("Auth: NTLM pass-the-hash");
    } else {
        debug!("Password: {}", _s_password);
    }
    debug!("DC: {:?}", s_dc);
    debug!("Kerberos: {:?}", kerberos);

    Ok(LdapArgs {
        s_url: s_url.to_string(),
        _s_dc: s_dc,
        _s_email: s_email.to_string().to_lowercase(),
        s_username: if use_ntlm {
            _s_username.to_string()
        } else {
            s_email.to_string().to_lowercase()
        },
        s_password: _s_password.to_string(),
        s_ntlm_password,
    })
}

/// Encode an NT hash into a password string that triggers pass-the-hash
/// in the sspi crate's NTLM implementation.
fn nt_hash_to_ntlm_password(hex_hash: &str) -> String {
    let upper = hex_hash.to_uppercase();
    let bytes = upper.as_bytes();

    let mut password = String::new();

    for pair in bytes.chunks(2) {
        let low_byte = pair[0] as u32;
        let high_byte = if pair.len() > 1 { pair[1] as u32 } else { 0 };
        let code_point = (high_byte << 8) | low_byte;
        password.push(char::from_u32(code_point).unwrap_or('\0'));
    }

    // Pad to exceed the 512-byte SSPI_CREDENTIALS_HASH_LENGTH_OFFSET
    for _ in 0..256 {
        password.push('\0');
    }

    password
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

/// Get all namingContext for DC
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
            
            // Put CN=Schema first so schema_guid_map is complete before ACEs are parsed
            naming_contexts.sort_by_key(|cn| {
                if cn.contains("CN=Schema") { 0 }
                else if cn.to_lowercase().starts_with("dc=") { 1 }
                else if cn.contains("CN=Configuration") { 2 }
                else { 3 }
            });

            // Trace sorted naming contexts order
            for (i, nc) in naming_contexts.iter().enumerate() {
                trace!("NamingContext order [{}]: {}", i, nc);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nt_hash_encoding_roundtrip() {
        let hash = "aad3b435b51404eeaad3b435b51404ee";
        let password = nt_hash_to_ntlm_password(hash);

        let utf16_bytes: Vec<u8> = password
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();

        assert!(utf16_bytes.len() > 512);

        let hash_portion = &utf16_bytes[..utf16_bytes.len() - 512];
        assert_eq!(hash_portion.len(), 32);

        let expected_hex = hash.to_uppercase();
        let expected_bytes = expected_hex.as_bytes();
        assert_eq!(hash_portion, expected_bytes);
    }

    #[test]
    fn nt_hash_encoding_all_zeros() {
        let hash = "00000000000000000000000000000000";
        let password = nt_hash_to_ntlm_password(hash);

        let utf16_bytes: Vec<u8> = password
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();

        assert!(utf16_bytes.len() > 512);
        let hash_portion = &utf16_bytes[..utf16_bytes.len() - 512];
        assert_eq!(hash_portion, b"00000000000000000000000000000000");
    }

    #[test]
    fn nt_hash_encoding_all_f() {
        let hash = "ffffffffffffffffffffffffffffffff";
        let password = nt_hash_to_ntlm_password(hash);

        let utf16_bytes: Vec<u8> = password
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();

        assert!(utf16_bytes.len() > 512);
        let hash_portion = &utf16_bytes[..utf16_bytes.len() - 512];
        assert_eq!(hash_portion, b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    }
}
