//! LDAP authentication and collection.
//!
//! [`ldap_auth`] connects and authenticates, returning a ready `Ldap` session.
//! The full workflow is `api::run_collection`; collection itself is
//! `collect_from_ldap_into`.

use crate::args::Options;
use crate::banner::progress_bar;
use crate::storage::Storage;
use crate::utils::format::domain_to_dc;

use colored::Colorize;
use indicatif::ProgressBar;
use ldap3::adapters::{Adapter, EntriesOnly};
use ldap3::exop::WhoAmI;
use ldap3::{adapters::PagedResults, controls::RawControl, LdapConnAsync, LdapConnSettings};
use ldap3::{Scope, SearchEntry};
use log::{info, debug, error, trace};
use std::io::{self, Write, stdin};
use std::collections::HashMap;
use std::error::Error;

/// Connect to the DC and authenticate, returning a ready `ldap3::Ldap` session.
/// The method is picked from `options`: certificate (`pfx` or `crt`/`key`),
/// NTLM pass-the-hash (`hashes`), Kerberos (`kerberos`), else simple bind.
/// Certificate auth defaults to StartTLS on 389, or LDAPS 636 with `--ldaps`.
/// The caller owns the session (never unbound here).
pub async fn ldap_auth(options: &Options) -> Result<ldap3::Ldap, Box<dyn Error>> {
    let use_cert = options.pfx.is_some() || options.crt.is_some();

    // Certificate transport: StartTLS by default, LDAPS with --ldaps.
    let starttls = use_cert && !options.ldaps;
    let effective_ldaps = if use_cert { !starttls } else { options.ldaps };
    let effective_port = if use_cert {
        options.port.or(Some(if starttls { 389 } else { 636 }))
    } else {
        options.port
    };

    let ldap_args = ldap_constructor(
        effective_ldaps,
        options.ip.as_deref(),
        effective_port,
        &options.domain,
        options.ldapfqdn.as_deref(),
        options.username.as_deref(),
        options.password.as_deref(),
        options.hashes.as_deref(),
        options.kerberos,
        use_cert,
    )?;

    let mut consettings = LdapConnSettings::new()
        .set_conn_timeout(std::time::Duration::from_secs(10))
        .set_no_tls_verify(true);
    if use_cert {
        let config = crate::transport::cert::build_client_config(
            options.pfx.as_deref(),
            options.pfx_pass.as_deref(),
            options.crt.as_deref(),
            options.key.as_deref(),
        )?;
        consettings = consettings.set_config(config);
        if starttls {
            consettings = consettings.set_starttls(true);
        }
    }

    let (conn, mut ldap) = LdapConnAsync::with_settings(consettings, &ldap_args.s_url).await?;
    ldap3::drive!(conn);

    let domain = &options.domain;

    if use_cert {
        // Pass-the-Certificate: SASL EXTERNAL over StartTLS, or implicit
        // Schannel mapping over LDAPS. Confirm the mapped identity with whoami.
        if starttls {
            debug!("Certificate authentication (StartTLS + SASL EXTERNAL)");
            ldap.sasl_external_bind()
                .await
                .and_then(|r| r.success())
                .map_err(|e| format!("certificate SASL EXTERNAL bind failed (try --ldaps): {e}"))?;
        } else {
            debug!("Certificate authentication (LDAPS, implicit Schannel mapping)");
        }
        let who = ldap
            .extended(WhoAmI)
            .await
            .map(|r| r.success())
            .map_err(|e| format!("certificate whoami request failed: {e}"))?
            .map_err(|e| format!("certificate whoami failed: {e}"))?
            .0
            .val
            .as_ref()
            .map(|v| String::from_utf8_lossy(v).to_string())
            .unwrap_or_default();
        if who.is_empty() {
            return Err(format!(
                "certificate not mapped by {} (empty whoami); check the cert SID and DC enforcement (KB5014754)",
                domain.to_uppercase()
            )
            .into());
        }
        info!(
            "Connected to {} Active Directory via certificate as {}!",
            domain.to_uppercase().bold().green(),
            who.bold().green()
        );
    } else if let Some(ref ntlm_password) = ldap_args.s_ntlm_password {
        debug!("NTLM pass-the-hash (sasl_ntlm_bind)");
        ldap.sasl_ntlm_bind(&ldap_args.s_username, ntlm_password)
            .await?
            .success()
            .map_err(|e| format!("NTLM authentication to {} failed: {e}", domain.to_uppercase()))?;
        info!("Connected to {} Active Directory via NTLM!", domain.to_uppercase().bold().green());
    } else if !options.kerberos {
        debug!("Simple bind (username:password)");
        ldap.simple_bind(&ldap_args.s_username, &ldap_args.s_password)
            .await?
            .success()
            .map_err(|e| format!("authentication to {} failed: {e}", domain.to_uppercase()))?;
        info!("Connected to {} Active Directory!", domain.to_uppercase().bold().green());
    } else {
        debug!("Kerberos (sasl_gssapi_bind)");
        let fqdn = options
            .ldapfqdn
            .as_deref()
            .filter(|f| !f.is_empty())
            .ok_or("Kerberos requires the Domain Controller FQDN (set options.ldapfqdn, e.g. DC01.DOMAIN.LOCAL)")?;
        #[cfg(not(feature = "nogssapi"))]
        {
            gssapi_connection(&mut ldap, fqdn, domain).await?;
        }
        #[cfg(feature = "nogssapi")]
        {
            let _ = fqdn;
            return Err("Kerberos/GSSAPI is not available in this build (nogssapi feature)".into());
        }
    }

    Ok(ldap)
}

/// Collect every namingContext into `storage` and return the object count.
/// Each context is walked with the SD-flags and show-deleted controls and
/// streamed into `storage`. The caller owns the session.
pub(crate) async fn collect_from_ldap_into<S: Storage<LdapSearchEntry>>(
    ldap: &mut ldap3::Ldap,
    ldapfilter: &str,
    storage: &mut S,
) -> Result<usize, Box<dyn Error>> {
    let mut total = 0usize;

    let res = get_all_naming_contexts(ldap).await?;
    trace!("naming_contexts: {:?}", &res);

    if !res.iter().any(|s| s.contains("Configuration")) {
        return Err("no Configuration namingContext found (is the target a Domain Controller?)".into());
    }

    for cn in &res {
        // Control 1: LDAP_SERVER_SD_FLAGS_OID to get nTSecurityDescriptor.
        let sd_flags = RawControl {
            ctype: String::from("1.2.840.113556.1.4.801"),
            crit: true,
            val: Some(vec![48, 3, 2, 1, 5]), // SEQUENCE { INTEGER 5 }
        };
        // Control 2: LDAP_SERVER_SHOW_DELETED_OID.
        let show_deleted = RawControl {
            ctype: String::from("1.2.840.113556.1.4.417"),
            crit: false,
            val: None,
        };
        ldap.with_controls(vec![sd_flags, show_deleted]);

        info!("Ldap filter : {}", ldapfilter.bold().green());

        let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
            Box::new(EntriesOnly::new()),
            Box::new(PagedResults::new(999)),
        ];

        let mut search = ldap
            .streaming_search_with(
                adapters,
                cn,
                Scope::Subtree,
                ldapfilter,
                vec!["*", "nTSecurityDescriptor", "msDS-User-Account-Control-Computed"],
            )
            .await?;

        // Ranged-retrieval side channel (#76): a cloned `Ldap` handle multiplexes
        // the follow-up queries over the same connection while the main stream is
        // consumed. The controls above were already taken by the search
        let mut ranged_ldap = ldap.clone();

        let pb = ProgressBar::new(1);
        let mut count = 0;
        while let Some(entry) = search.next().await? {
            let mut entry = SearchEntry::construct(entry);
            complete_ranged_attributes(&mut ranged_ldap, &mut entry).await?;
            total += 1;
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

        match search.finish().await.success() {
            Ok(_) => info!("All data collected for NamingContext {}", &cn.bold()),
            Err(err) => error!("No data collected on {}! Reason: {err}", &cn.bold().red()),
        }
    }

    storage.flush()?;
    Ok(total)
}

/// Complete attributes truncated by AD ranged retrieval, then re-key the values
/// under the plain attribute name so parsers (e.g. the `"member"` arm in
/// `objects::group`) see them unchanged.
///
/// Past `MaxValRange` (default 1500) AD renames an attribute to
/// `attr;range=0-1499` and drops the plain key, why groups with >1499 members
/// looked empty (#76). Each chunk is fetched with base-scoped
/// `attr;range=<next>-*` queries until the final `-*` chunk. Generic (covers
/// `member`, `memberOf`, …); a no-op for normal entries.
async fn complete_ranged_attributes(
    ldap: &mut ldap3::Ldap,
    entry: &mut SearchEntry,
) -> Result<(), Box<dyn Error>> {
    // Attributes returned as `name;range=low-high` (AD may capitalise `Range`).
    let ranged: Vec<(String, String)> = entry
        .attrs
        .keys()
        .filter_map(|k| {
            let (base, opt) = k.split_once(';')?;
            if opt.to_ascii_lowercase().starts_with("range=") {
                Some((k.to_string(), base.to_string()))
            } else {
                None
            }
        })
        .collect();

    for (ranged_key, base_attr) in ranged {
        // Take the first chunk's values, re-keyed under `base_attr` later.
        let mut values = entry.attrs.remove(&ranged_key).unwrap_or_default();

        let mut next_start = match range_high(&ranged_key) {
            Some(high) => high + 1,
            None => {
                // Already `-*`: single chunk, just rename.
                entry.attrs.entry(base_attr).or_default().append(&mut values);
                continue;
            }
        };

        debug!("Ranged attribute '{}' on {} exceeds MaxValRange; retrieving remaining values", base_attr.bold().yellow(), entry.dn.bold());

        // Pull the remaining chunks: `base_attr;range=<next_start>-*`.
        loop {
            let want = format!("{base_attr};range={next_start}-*");
            let (rs, _res) = ldap
                .search(&entry.dn, Scope::Base, "(objectClass=*)", vec![want.as_str()])
                .await?
                .success()?;

            let Some(re) = rs.into_iter().next() else { break };
            let chunk = SearchEntry::construct(re);

            // Find the returned ranged key.
            let found = chunk.attrs.iter().find_map(|(k, _)| {
                let (b, opt) = k.split_once(';')?;
                if b.eq_ignore_ascii_case(&base_attr)
                    && opt.to_ascii_lowercase().starts_with("range=")
                {
                    Some((k.clone(), opt.ends_with("-*")))
                } else {
                    None
                }
            });

            let Some((key, is_last)) = found else { break };

            if let Some(v) = chunk.attrs.get(&key) {
                values.extend(v.iter().cloned());
            }

            if is_last {
                break; // final chunk
            }
            match range_high(&key) {
                Some(high) => next_start = high + 1,
                None => break,
            }
        }

        trace!("'{}' on {}: {} values after ranged retrieval", base_attr, entry.dn, values.len());
        entry.attrs.entry(base_attr).or_default().append(&mut values);
    }

    Ok(())
}

/// High bound of a `...;range=low-high` descriptor. `None` for `-*` (final
/// chunk) or an unparsable range — both meaning "complete" to the caller.
fn range_high(key: &str) -> Option<usize> {
    let opt = key.split(';').nth(1)?;      // range=low-high
    let spec = opt.split_once('=')?.1;     // low-high
    let high = spec.split_once('-')?.1;    // high
    high.parse::<usize>().ok()
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
#[allow(clippy::too_many_arguments)]
fn ldap_constructor(
    ldaps: bool,
    ip: Option<&str>,
    port: Option<u16>,
    domain: &str,
    ldapfqdn: Option<&str>,
    username: Option<&str>,
    password: Option<&str>,
    hashes: Option<&str>,
    kerberos: bool,
    use_cert: bool,
) -> Result<LdapArgs, Box<dyn Error>> {
    let s_url = prepare_ldap_url(ldaps, ip, port, domain);
    let s_dc = prepare_ldap_dc(domain);
    let use_ntlm = hashes.is_some();

    // Username prompt (skipped for Kerberos and certificate auth)
    let mut s = String::new();
    let mut _s_username: String;
    if username.is_none() && !kerberos && !use_cert {
        print!("Username: ");
        io::stdout().flush()?;
        stdin().read_line(&mut s).expect("Did not enter a correct username");
        io::stdout().flush()?;
        if let Some('\n') = s.chars().next_back() { s.pop(); }
        if let Some('\r') = s.chars().next_back() { s.pop(); }
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
            let nt = match clean.split_once(':') {
                Some((_lm, nt)) => nt,
                None => clean,
            };
            if nt.len() != 32 || !nt.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err("Invalid NT hash: must be exactly 32 hex characters (e.g. aad3b435b51404eeaad3b435b51404ee)".into());
            }
            Some(nt_hash_to_ntlm_password(nt))
        }
        None => None,
    };

    // Password prompt (skip for NTLM hash, Kerberos, and certificate auth)
    let mut _s_password: String = String::new();
    if !use_ntlm && !_s_username.contains("not set") && !kerberos && !use_cert {
        _s_password = match password {
            Some(p) => p.to_owned(),
            None => rpassword::prompt_password("Password: ").unwrap_or("not set".to_string()),
        };
    } else {
        _s_password = password.unwrap_or("not set").to_owned();
    }

    debug!("IP: {}", ip.unwrap_or("not set"));
    debug!("PORT: {}", match port { Some(p) => p.to_string(), None => "not set".to_owned() });
    debug!("FQDN: {}", ldapfqdn.unwrap_or("not set"));
    debug!("Url: {}", s_url);
    debug!("Domain: {}", domain);
    debug!("Username: {}", _s_username);
    debug!("Email: {}", s_email.to_lowercase());
    if use_cert {
        debug!("Auth: certificate (Pass-the-Certificate)");
    } else if use_ntlm {
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
        s_username: if use_ntlm { _s_username.to_string() } else { s_email.to_string().to_lowercase() },
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
    for _ in 0..256 {
        password.push('\0');
    }
    password
}

/// Function to prepare LDAP url.
fn prepare_ldap_url(ldaps: bool, ip: Option<&str>, port: Option<u16>, domain: &str) -> String {
    let protocol = if ldaps || port.unwrap_or(0) == 636 { "ldaps" } else { "ldap" };
    let target = match ip { Some(ip) => ip, None => domain };
    match port {
        Some(port) => format!("{protocol}://{target}:{port}"),
        None => format!("{protocol}://{target}"),
    }
}

/// Function to prepare LDAP DC from DOMAIN.LOCAL
pub fn prepare_ldap_dc(domain: &str) -> Vec<String> {
    let mut dc: String = "".to_owned();
    let mut naming_context: Vec<String> = Vec::new();
    if !domain.contains(".") {
        dc.push_str("DC=");
        dc.push_str(domain);
        naming_context.push(dc[..].to_string());
    } else {
        naming_context.push(domain_to_dc(domain));
    }
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
    ldap.sasl_gssapi_bind(ldapfqdn)
        .await?
        .success()
        .map_err(|e| format!("Kerberos authentication to {} failed: {e}", domain.to_uppercase()))?;
    info!("Connected to {} Active Directory!", domain.to_uppercase().bold().green());
    Ok(())
}

/// Get all namingContext for DC
pub async fn get_all_naming_contexts(ldap: &mut ldap3::Ldap) -> Result<Vec<String>, Box<dyn Error>> {
    let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResults::new(999)),
    ];
    let mut search = ldap.streaming_search_with(
        adapters,
        "",
        Scope::Base,
        "(objectClass=*)",
        vec!["namingContexts"],
    ).await?;

    let mut rs: Vec<SearchEntry> = Vec::new();
    while let Some(entry) = search.next().await? {
        rs.push(SearchEntry::construct(entry));
    }
    let res = search.finish().await.success();

    let mut naming_contexts: Vec<String> = Vec::new();
    match res {
        Ok(_res) => {
            debug!("All namingContexts collected!");
            for result in rs {
                for (_key, value) in &result.attrs {
                    for naming_context in value {
                        debug!("namingContext found: {}", &naming_context.bold().green());
                        naming_contexts.push(naming_context.to_string());
                    }
                }
            }
            naming_contexts.sort_by_key(|cn| {
                if cn.contains("CN=Schema") { 0 }
                else if cn.to_lowercase().starts_with("dc=") { 1 }
                else if cn.contains("CN=Configuration") { 2 }
                else { 3 }
            });
            for (i, nc) in naming_contexts.iter().enumerate() {
                trace!("NamingContext order [{}]: {}", i, nc);
            }
            return Ok(naming_contexts);
        }
        Err(err) => {
            error!("No namingContexts found! Reason: {err}");
        }
    }
    Ok(Vec::new())
}

// New type to implement Serialize and Deserialize for SearchEntry
#[derive(Debug, Clone, bincode::Encode, bincode::Decode)]
pub struct LdapSearchEntry {
    pub dn: String,
    pub attrs: HashMap<String, Vec<String>>,
    pub bin_attrs: HashMap<String, Vec<Vec<u8>>>,
}

impl From<SearchEntry> for LdapSearchEntry {
    fn from(entry: SearchEntry) -> Self {
        LdapSearchEntry { dn: entry.dn, attrs: entry.attrs, bin_attrs: entry.bin_attrs }
    }
}

impl From<LdapSearchEntry> for SearchEntry {
    fn from(entry: LdapSearchEntry) -> Self {
        SearchEntry { dn: entry.dn, attrs: entry.attrs, bin_attrs: entry.bin_attrs }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_high_parsing() {
        assert_eq!(range_high("member;range=0-1499"), Some(1499));
        assert_eq!(range_high("member;range=1500-2999"), Some(2999));
        assert_eq!(range_high("member;range=3000-*"), None); // final chunk
        assert_eq!(range_high("member"), None); // not ranged
        assert_eq!(range_high("member;range=bad"), None); // unparsable
    }

    #[test]
    fn nt_hash_encoding_roundtrip() {
        let hash = "aad3b435b51404eeaad3b435b51404ee";
        let password = nt_hash_to_ntlm_password(hash);
        let utf16_bytes: Vec<u8> = password.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        assert!(utf16_bytes.len() > 512);
        let hash_portion = &utf16_bytes[..utf16_bytes.len() - 512];
        assert_eq!(hash_portion.len(), 32);
        assert_eq!(hash_portion, hash.to_uppercase().as_bytes());
    }

    #[test]
    fn nt_hash_encoding_all_zeros() {
        let hash = "00000000000000000000000000000000";
        let password = nt_hash_to_ntlm_password(hash);
        let utf16_bytes: Vec<u8> = password.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        assert!(utf16_bytes.len() > 512);
        let hash_portion = &utf16_bytes[..utf16_bytes.len() - 512];
        assert_eq!(hash_portion, b"00000000000000000000000000000000");
    }

    #[test]
    fn nt_hash_encoding_all_f() {
        let hash = "ffffffffffffffffffffffffffffffff";
        let password = nt_hash_to_ntlm_password(hash);
        let utf16_bytes: Vec<u8> = password.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        assert!(utf16_bytes.len() > 512);
        let hash_portion = &utf16_bytes[..utf16_bytes.len() - 512];
        assert_eq!(hash_portion, b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    }
}