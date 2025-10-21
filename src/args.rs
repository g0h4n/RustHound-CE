//! Parsing arguments
#[cfg(not(feature = "noargs"))]
use clap::{Arg, ArgAction, value_parser, Command};

#[cfg(feature = "noargs")]
use winreg::{RegKey,{enums::*}};
#[cfg(feature = "noargs")]
use crate::utils::exec::run;
#[cfg(feature = "noargs")]
use regex::Regex;

#[derive(Clone, Debug)]
pub struct Options {
    pub domain: String,
    pub username: Option<String>,
    // pub password: Option<String>,
    // pub ntlm_hash: Option<ldap3::NtlmHash>,
    pub auth: Option<LdapAuth>,
    pub ldapfqdn: String,
    pub ip: Option<String>,
    pub port: Option<u16>,
    pub name_server: String,
    pub path: String,
    pub collection_method: CollectionMethod,
    pub ldaps: bool,
    pub dns_tcp: bool,
    pub fqdn_resolver: bool,
    pub kerberos: bool,
    pub zip: bool,
    pub verbose: log::LevelFilter,
    pub ldap_filter: String,

    pub cache: bool,
    pub cache_buffer_size: usize,
    pub resume: bool,
}

#[derive(Clone, Debug)]
pub enum CollectionMethod {
    All,
    DCOnly,
}

#[derive(Debug, Clone)]
pub enum LdapAuth {
    Password(String),
    Ntlm(ldap3::NtlmHash)
}

// Current RustHound version
pub const RUSTHOUND_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(not(feature = "noargs"))]
fn cli() -> Command {
    // Return Command args
    Command::new("rusthound-ce")
    .version(RUSTHOUND_VERSION)
    .about("Active Directory data collector for BloodHound Community Edition.\ng0h4n <https://twitter.com/g0h4n_0>")
    .arg(Arg::new("v")
        .short('v')
        .help("Set the level of verbosity")
        .action(ArgAction::Count),
    )
    .next_help_heading("REQUIRED VALUES")
    .arg(Arg::new("domain")
        .short('d')
        .long("domain")
            .help("Domain name like: DOMAIN.LOCAL")
            .required(true)
            .value_parser(value_parser!(String))
    )
    .next_help_heading("OPTIONAL VALUES")
    .arg(Arg::new("ldapusername")
        .short('u')
        .long("ldapusername")
        .help("LDAP username, like: user@domain.local")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("ldappassword")
        .short('p')
        .long("ldappassword")
        .help("LDAP password")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("ldapntlmhash")
        .short('H')
        .long("ldapntlmhash")
        .help("LDAP NTLM hash")
        .required(false)
        .conflicts_with("ldappassword")
        .value_parser(value_parser!(ldap3::NtlmHash))
    )
    .arg(Arg::new("ldapfqdn")
        .short('f')
        .long("ldapfqdn")
        .help("Domain Controller FQDN like: DC01.DOMAIN.LOCAL or just DC01")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("ldapip")
        .short('i')
        .long("ldapip")
        .help("Domain Controller IP address like: 192.168.1.10")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("ldapport")
        .short('P')
        .long("ldapport")
        .help("LDAP port [default: 389]")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("name-server")
        .short('n')
        .long("name-server")
        .help("Alternative IP address name server to use for DNS queries")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("output")
        .short('o')
        .long("output")
        .help("Output directory where you would like to save JSON files [default: ./]")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .next_help_heading("OPTIONAL FLAGS")
    .arg(Arg::new("collectionmethod")
        .short('c')
        .long("collectionmethod")
        .help("Which information to collect. Supported: All (LDAP,SMB,HTTP requests), DCOnly (no computer connections, only LDAP requests). (default: All)")
        .required(false)
        .value_name("COLLECTIONMETHOD")
        .value_parser(["All", "DCOnly"])
        .num_args(0..=1)
        .default_missing_value("All")
    )
    .arg(Arg::new("ldap-filter")
        .long("ldap-filter")
        .help("Use custom ldap-filter default is : (objectClass=*)")
        .required(false)
        .value_parser(value_parser!(String))
        .default_missing_value("(objectClass=*)")
    )
    .arg(Arg::new("ldaps")
        .long("ldaps")
        .help("Force LDAPS using for request like: ldaps://DOMAIN.LOCAL/")
        .required(false)
        .action(ArgAction::SetTrue)
        .global(false)
    )
    .arg(Arg::new("kerberos")
        .short('k')
        .long("kerberos")
        .help("Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters for Linux.")
        .required(false)
        .action(ArgAction::SetTrue)
        .global(false)
    )
    .arg(Arg::new("dns-tcp")
        .long("dns-tcp")
        .help("Use TCP instead of UDP for DNS queries")
        .required(false)
        .action(ArgAction::SetTrue)
        .global(false)
    )
    .arg(Arg::new("zip")
        .long("zip")
        .short('z')
        .help("Compress the JSON files into a zip archive")
        .required(false)
        .action(ArgAction::SetTrue)
        .global(false)
    )
    .arg(Arg::new("cache")
        .long("cache")
        .help("Cache LDAP search results to disk (reduce memory usage on large domains)")
        .required(false)
        .action(ArgAction::SetTrue)
    )
    .arg(Arg::new("cache_buffer")
        .long("cache-buffer")
        .help("Buffer size to use when caching")
        .required(false)
        .value_parser(value_parser!(usize))
        .default_value("1000")
    )
    .arg(Arg::new("resume")
        .long("resume")
        .help("Resume the collection from the last saved state")
        .required(false)
        .action(ArgAction::SetTrue)
    )
    .next_help_heading("OPTIONAL MODULES")
    .arg(Arg::new("fqdn-resolver")
        .long("fqdn-resolver")
        .help("Use fqdn-resolver module to get computers IP address")
        .required(false)
        .action(ArgAction::SetTrue)
        .global(false)
    )
}

#[cfg(not(feature = "noargs"))]
/// Function to extract all argument and put it in 'Options' structure.
pub fn extract_args() -> Options {

    // Get arguments
    let matches = cli().get_matches();

    // Now get values
    let d = matches
        .get_one::<String>("domain")
        .map(|s| s.as_str())
        .unwrap();
    let username = matches
        .get_one::<String>("ldapusername")
        .map(|s| s.to_owned());
    let password = matches
        .get_one::<String>("ldappassword")
        .map(|s| s.to_owned());
    let ntlm_hash = matches
        .get_one::<ldap3::NtlmHash>("ldapntlmhash")
        .cloned();
    let f = matches
        .get_one::<String>("ldapfqdn")
        .map(|s| s.as_str())
        .unwrap_or("not set");
    let ip = matches.get_one::<String>("ldapip").cloned();    
    let port = match matches.get_one::<String>("ldapport") {
        Some(val) => val.parse::<u16>().ok(),
        None => None,
    };
    let n = matches
        .get_one::<String>("name-server")
        .map(|s| s.as_str())
        .unwrap_or("not set");
    let path = matches
        .get_one::<String>("output")
        .map(|s| s.as_str())
        .unwrap_or("./");
    let ldaps = matches
        .get_one::<bool>("ldaps")
        .map(|s| s.to_owned())
        .unwrap_or(false);
    let dns_tcp = matches
        .get_one::<bool>("dns-tcp")
        .map(|s| s.to_owned())
        .unwrap_or(false);
    let z = matches
        .get_one::<bool>("zip")
        .map(|s| s.to_owned())
        .unwrap_or(false);
    let fqdn_resolver = matches
        .get_one::<bool>("fqdn-resolver")
        .map(|s| s.to_owned())
        .unwrap_or(false);
    let kerberos = matches
        .get_one::<bool>("kerberos")
        .map(|s| s.to_owned())
        .unwrap_or(false);
    let v = match matches.get_count("v") {
        0 => log::LevelFilter::Info,
        1 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };
    let collection_method = match matches.get_one::<String>("collectionmethod").map(|s| s.as_str()).unwrap_or("All") {
        "All"       => CollectionMethod::All,
        "DCOnly"    => CollectionMethod::DCOnly,
         _          => CollectionMethod::All,
    };
    let ldap_filter = matches.get_one::<String>("ldap-filter").map(|s| s.as_str()).unwrap_or("(objectClass=*)");

    let cache = matches.get_flag("cache");
    let cache_buffer_size = matches
        .get_one::<usize>("cache_buffer")
        .copied()
        .unwrap_or(1000);
    let resume = matches.get_flag("resume");

    let auth = match (password, ntlm_hash) {
        (Some(p), None) => Some(LdapAuth::Password(p)),
        (None, Some(h)) => Some(LdapAuth::Ntlm(h)),
        (None, None) => None,
        _ => unreachable!(), // clap `conflicts_with` prevents this 
    };

    // Return all
    Options {
        domain: d.to_string(),
        username,
        auth,
        ldapfqdn: f.to_string(),
        ip,
        port,
        name_server: n.to_string(),
        path: path.to_string(),
        collection_method,
        ldaps,
        dns_tcp,
        fqdn_resolver,
        kerberos,
        zip: z,
        verbose: v,
        ldap_filter: ldap_filter.to_string(),
        cache,
        cache_buffer_size,
        resume,
    }
}

#[cfg(feature = "noargs")]
/// Function to automatically get all informations needed and put it in 'Options' structure.
pub fn auto_args() -> Options {

    // Request registry key to get informations
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let cur_ver = hklm.open_subkey("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters").unwrap();
    //Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Domain
    let domain: String = match cur_ver.get_value("Domain") {
        Ok(domain) => domain,
        Err(err) => {
            panic!("Error: {:?}",err);
        }
    };
    
    // Get LDAP fqdn
    let _fqdn: String = run(&format!("nslookup -query=srv _ldap._tcp.{}",&domain));
    let re = Regex::new(r"hostname.*= (?<ldap_fqdn>[0-9a-zA-Z]{1,})").unwrap();
    let mut values =  re.captures_iter(&_fqdn);
    let caps = values.next().unwrap();
    let fqdn = caps["ldap_fqdn"].to_string();

    // Get LDAP port
    let re = Regex::new(r"port.*= (?<ldap_port>[0-9]{3,})").unwrap();
    let mut values =  re.captures_iter(&_fqdn);
    let caps = values.next().unwrap();
    let port = match caps["ldap_port"].to_string().parse::<u16>() {
        Ok(x) => Some(x),
        Err(_) => None
    };
    let ldaps: bool = {
        if let Some(p) = port {
            p == 636
        } else {
            false
        }
    };

    // Return all
    Options {
        domain: domain.to_string(),
        username: "not set".to_string(),
        // password: "not set".to_string(),
        // ntlm_hash: None,
        auth: None,
        ldapfqdn: fqdn.to_string(),
        ip: None, 
        port: port,
        name_server: "127.0.0.1".to_string(),
        path: "./output".to_string(),
        collection_method: CollectionMethod::All,
        ldaps: ldaps,
        dns_tcp: false,
        fqdn_resolver: false,
        kerberos: true,
        zip: true,
        verbose: log::LevelFilter::Info,
        ldap_filter: "(objectClass=*)".to_string(),
        cache: false,
        cache_buffer_size: 1000,
        resume: false,
    }
}
