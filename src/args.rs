//! Parsing arguments
use log::{info,debug,trace};
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
    pub password: Option<String>,
    pub ldapfqdn: Option<String>,
    pub ip: Option<String>,
    pub port: Option<u16>,
    pub name_server: String,
    pub path: String,
    pub collection_method: CollectionMethod,
    pub ldaps: bool,
    pub transport: Transport,
    pub dns_tcp: bool,
    pub fqdn_resolver: bool,
    pub hashes: Option<String>,
    pub kerberos: bool,
    // Certificate authentication (Pass-the-Certificate / Schannel)
    pub pfx: Option<String>,
    pub pfx_pass: Option<String>,
    pub crt: Option<String>,
    pub key: Option<String>,
    pub zip: bool,
    pub verbose: log::LevelFilter,
    pub ldap_filter: String,
    pub cache: bool,
    pub cache_buffer_size: usize,
    pub resume: bool,
    // Collection tuning / OPSEC (SMB/RPC side)
    pub ldap_timeout: std::time::Duration,
    pub smb_timeout: std::time::Duration,
    pub host_timeout: std::time::Duration,
    pub http_timeout: std::time::Duration,
    pub computer_expiry_days: i64,
    pub workers: usize,
    pub throttle: u64,
    pub jitter: u64,
    pub opsec: bool,
}

impl Options {
    /// True when authenticating with a client certificate (no SMB credentials
    /// are available, so SMB-based modules must be skipped).
    pub fn uses_cert(&self) -> bool {
        self.pfx.is_some() || self.crt.is_some()
    }

    /// Log every parsed argument 
    pub fn trace_values(&self) {
        let secret = |o: &Option<String>| {
            if o.as_deref().is_some_and(|s| !s.is_empty()) { "[REDACTED]" } else { "not set" }
        };

        info!("Verbosity level: {:?}", self.verbose);
        info!("Collection method: {:?}", self.collection_method);
        // Essentials, shown by default.
        info!("Domain: {:?}", self.domain);
        info!("Username: {:?}", self.username);
        info!("Output path: {:?}", self.path);
        info!("Transport: {:?}", self.transport);

        // Connection details, shown at -v.
        debug!("IP: {:?}", self.ip);
        debug!("Port: {:?}", self.port);
        debug!("LDAP FQDN: {:?}", self.ldapfqdn);
        debug!("Name server: {:?}", self.name_server);
        debug!("LDAPS: {}", self.ldaps);
        debug!("Kerberos: {}", self.kerberos);
        debug!("Password: {}", secret(&self.password));
        debug!("Hashes: {}", secret(&self.hashes));
        debug!("FQDN resolver: {}", self.fqdn_resolver);
        debug!("Zip: {}", self.zip);
        debug!("Cache: {}", self.cache);
        debug!("Resume: {}", self.resume);
        debug!("OPSEC: {}", self.opsec);
        debug!("LDAP filter: {:?}", self.ldap_filter);

        // Fine-grained tuning, shown at -vv.
        trace!("PFX: {:?}", self.pfx);
        trace!("PFX pass: {}", secret(&self.pfx_pass));
        trace!("CRT: {:?}", self.crt);
        trace!("Key: {:?}", self.key);
        trace!("DNS TCP: {}", self.dns_tcp);
        trace!("Cache buffer size: {}", self.cache_buffer_size);
        trace!("LDAP timeout: {:?}", self.ldap_timeout);
        trace!("SMB timeout: {:?}", self.smb_timeout);
        trace!("Host timeout: {:?}", self.host_timeout);
        trace!("HTTP timeout: {:?}", self.http_timeout);
        trace!("Workers: {}", self.workers);
        trace!("Throttle: {}", self.throttle);
        trace!("Jitter: {}", self.jitter);
        trace!("Computer expiry days: {}", self.computer_expiry_days);
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum CollectionMethod {
    All,            // LDAP|ADWS(SOAP) + Session (all three RPC paths) + SMB on SYSVOL + LocalGroup 
    DCOnly,         // LDAP|ADWS(SOAP) only, never contacts a machine + SMB on SYSVOL
    Session,        // LDAP|ADWS(SOAP) + SRVSVC + WKSSVC + WINREG 
    RegistryOnly,   // LDAP|ADWS(SOAP) + WINREG
    LdapOnly,       // LDAP
    GPOLocalGroup,  // LDAP|ADWS(SOAP) + GPOLocalGroup with SMB on SYSVOL
    LocalGroup,     // LDAP|ADWS(SOAP) + RPC SAMR
    WebClient,      // LDAP|ADWS(SOAP) + SMB WebDAV pipe probe (IsWebClientRunning)
    CARegistry,     // LDAP|ADWS(SOAP) + MS-RRP \winreg CA registry values (CARegistryData)
    SOAPOnly,       // ADWS(SOAP)
}

impl CollectionMethod {
    pub fn does_session(&self)      -> bool { self.srvsvc() || self.wkssvc() || self.registry() }
    pub fn srvsvc(&self)            -> bool { matches!(self, Self::All | Self::Session) }
    pub fn wkssvc(&self)            -> bool { matches!(self, Self::All | Self::Session) }
    pub fn registry(&self)          -> bool { matches!(self, Self::All | Self::Session | Self::RegistryOnly) }
    pub fn does_gpo(&self)          -> bool { matches!(self, Self::All | Self::DCOnly | Self::GPOLocalGroup) }
    pub fn does_local_group(&self)  -> bool { matches!(self, Self::All | Self::LocalGroup) }
    pub fn does_web_client(&self)   -> bool { matches!(self, Self::All | Self::WebClient) }
    pub fn does_ca_registry(&self)  -> bool { matches!(self, Self::All | Self::CARegistry) }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Transport {
    Ldap,
    Soap,
}

// Current RustHound version
pub const RUSTHOUND_VERSION: &str = env!("CARGO_PKG_VERSION");

// --opsec stealth preset values, applied only to flags the user did not set.
const OPSEC_WORKERS: usize = 1;         // far fewer concurrent SMB sessions
const OPSEC_THROTTLE_MS: u64 = 1_000;   // base delay before each connection
const OPSEC_JITTER_MS: u64 = 1_000;     // random extra delay on top of throttle
const OPSEC_LDAP_FILTER: &str = "(!(RustHoundCEFilter=*))";

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
    .arg(Arg::new("hashes")
        .short('H')
        .long("hashes")
        .help("NT hash for pass-the-hash authentication (NTLM), accept [NTHASH, :NTHASH, LMHASH:NTHASH]")
        .required(false)
        .value_parser(value_parser!(String))
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
        .help("LDAP port [default: 389, or 636 with --ldaps]")
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
    .next_help_heading("CERTIFICATE AUTHENTICATION")
    .arg(Arg::new("pfx")
        .long("pfx")
        .help("PFX/PKCS#12 client certificate for certificate authentication (Pass-the-Certificate). Uses StartTLS by default, or LDAPS with --ldaps")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("pfx-pass")
        .long("pfx-pass")
        .help("Password protecting the PFX file (optional)")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("crt")
        .long("crt")
        .help("PEM client certificate for certificate authentication (use with --key)")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("key")
        .long("key")
        .help("PEM private key for certificate authentication (use with --crt)")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .next_help_heading("OPTIONAL FLAGS")
    .arg(Arg::new("transport")
        .short('t')
        .long("transport")
        .help("Directory transport: ldap (default) or adws|soap (ADWS over TCP 9389)")
        .required(false)
        .value_name("TRANSPORT")
        .num_args(1)
        .default_value("ldap")
    )
    .arg(Arg::new("collectionmethod")
        .short('c')
        .long("collectionmethod")
        .help("Which information to collect. Supported: All (LDAP, SMB, HTTP), DCOnly (LDAP + SYSVOL, no member-machine connections), Session (user sessions over RPC), RegistryOnly (sessions over WINREG), LdapOnly (LDAP only, no machine or SYSVOL), GPOLocalGroup (LDAP + SMB SYSVOL for read local group member over GPO), LocalGroup (LDAP + SAMR BUILTIN alias membership), WebClient (LDAP + SMB WebDAV pipe probe for IsWebClientRunning), CARegistry (LDAP + MS-RRP winreg for the CA registry values IsUserSpecifiesSanEnabled and RoleSeparationEnabled), SOAPOnly|ADWSOnly to only use Active Directory Web Services protocol (default: All)")
        .value_name("COLLECTIONMETHOD")
        .value_parser(["All", "DCOnly", "Session", "RegistryOnly", "LdapOnly", "GPOLocalGroup", "LocalGroup", "WebClient", "CARegistry", "SOAPOnly", "ADWSOnly"])
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
    .next_help_heading("COLLECTION TUNING / OPSEC")
    .arg(Arg::new("ldap_timeout")
        .long("ldap-timeout")
        .help("Connection timeout in milliseconds for the directory transport over LDAP. Useful over slow links such as SOCKS/proxychains")
        .required(false)
        .value_name("MS")
        .value_parser(value_parser!(u64))
        .default_value("10000")
    )
    .arg(Arg::new("smb_timeout")
        .long("smb-timeout")
        .help("TCP/445 reachability pre-check timeout, in milliseconds")
        .required(false)
        .value_name("MS")
        .value_parser(value_parser!(u64))
        .default_value("1000")
    )
    .arg(Arg::new("host_timeout")
        .long("host-timeout")
        .help("Whole per-host budget (connect + auth + probe), in milliseconds")
        .required(false)
        .value_name("MS")
        .value_parser(value_parser!(u64))
        .default_value("8000")
    )
    .arg(Arg::new("http_timeout")
        .long("http-timeout")
        .help("ADCS ESC8 web-enrollment probe timeout (TCP + HTTP + HTTPS), in milliseconds")
        .required(false)
        .value_name("MS")
        .value_parser(value_parser!(u64))
        .default_value("2000")
    )
    .arg(Arg::new("computer_expiry_days")
        .long("computer-expiry-days")
        .help("Only probe computers whose pwdLastSet is within N days (SharpHound ComputerExpiryDays)")
        .required(false)
        .value_name("DAYS")
        .value_parser(value_parser!(i64))
        .default_value("60")
    )
    .arg(Arg::new("workers")
        .long("workers")
        .help("Max concurrent in-flight SMB sessions (bounded stream)")
        .required(false)
        .value_name("N")
        .value_parser(value_parser!(usize))
        .default_value("50")
    )
    .arg(Arg::new("throttle")
        .long("throttle")
        .help("Base delay before each SMB/RPC connection, in milliseconds (SharpHound --Throttle)")
        .required(false)
        .value_name("MS")
        .value_parser(value_parser!(u64))
        .default_value("0")
    )
    .arg(Arg::new("jitter")
        .long("jitter")
        .help("Random extra delay added on top of --throttle, in milliseconds (SharpHound --Jitter)")
        .required(false)
        .value_name("MS")
        .value_parser(value_parser!(u64))
        .default_value("0")
    )
    .arg(Arg::new("opsec")
        .long("opsec")
        .help("Stealth preset: shuffle target order, lower --workers, add --throttle/--jitter (explicit CLI values win)")
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
    let hashes = matches
        .get_one::<String>("hashes")
        .map(|s| s.to_owned());
    let f = matches.get_one::<String>("ldapfqdn").cloned();
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
    // Certificate authentication paths
    let pfx = matches.get_one::<String>("pfx").cloned();
    let pfx_pass = matches.get_one::<String>("pfx-pass").cloned();
    let crt = matches.get_one::<String>("crt").cloned();
    let key = matches.get_one::<String>("key").cloned();
    let v = match matches.get_count("v") {
        0 => log::LevelFilter::Info,
        1 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };
    let collection_method = match matches
        .get_one::<String>("collectionmethod")
        .map(|s| s.as_str())
        .unwrap_or("All")
    {
        "All"           => CollectionMethod::All,
        "DCOnly"        => CollectionMethod::DCOnly,
        "Session"       => CollectionMethod::Session,
        "RegistryOnly"  => CollectionMethod::RegistryOnly,
        "LdapOnly"      => CollectionMethod::LdapOnly,
        "GPOLocalGroup" => CollectionMethod::GPOLocalGroup,
        "LocalGroup"    => CollectionMethod::LocalGroup,
        "WebClient"     => CollectionMethod::WebClient,
        "CARegistry"    => CollectionMethod::CARegistry,
        "SOAPOnly"      => CollectionMethod::SOAPOnly,
        "ADWSOnly"      => CollectionMethod::SOAPOnly,
        _               => CollectionMethod::All,
    };
    let transport = match matches
        .get_one::<String>("transport")
        .map(|s| s.to_ascii_lowercase())
        .as_deref()
    {
        Some("soap") | Some("adws") => Transport::Soap,
        _ => Transport::Ldap,
    };
    // SOAPOnly only makes sense over the ADWS/SOAP transport
    if collection_method == CollectionMethod::SOAPOnly && transport != Transport::Soap {
        eprintln!("-c SOAPOnly or -c ADWSOnly requires --transport soap or -t adws");
        std::process::exit(1);
    }
    let mut ldap_filter = matches
        .get_one::<String>("ldap-filter")
        .map(|s| s.to_string())
        .unwrap_or_else(|| "(objectClass=*)".to_string());
    let cache = matches.get_flag("cache");
    let cache_buffer_size = matches
        .get_one::<usize>("cache_buffer")
        .copied()
        .unwrap_or(1000);
    let resume = matches.get_flag("resume");
    let ldap_timeout = std::time::Duration::from_millis(
        matches.get_one::<u64>("ldap_timeout").copied().unwrap_or(10_000),
    );
    let smb_timeout = std::time::Duration::from_millis(
        matches.get_one::<u64>("smb_timeout").copied().unwrap_or(10_00),
    );
    let host_timeout = std::time::Duration::from_millis(
        matches.get_one::<u64>("host_timeout").copied().unwrap_or(8_000),
    );
    let http_timeout = std::time::Duration::from_millis(
        matches.get_one::<u64>("http_timeout").copied().unwrap_or(2_000),
    );
    let computer_expiry_days = matches.get_one::<i64>("computer_expiry_days").copied().unwrap_or(60);
    let mut workers = matches.get_one::<usize>("workers").copied().unwrap_or(50).max(1);
    let mut throttle = matches.get_one::<u64>("throttle").copied().unwrap_or(0);
    let mut jitter = matches.get_one::<u64>("jitter").copied().unwrap_or(0);
    let opsec = matches.get_flag("opsec");
    if opsec {
        use clap::parser::ValueSource;
        let is_explicit = |id: &str| matches.value_source(id) == Some(ValueSource::CommandLine);
        if !is_explicit("workers")  { workers = OPSEC_WORKERS; }
        if !is_explicit("throttle") { throttle = OPSEC_THROTTLE_MS; }
        if !is_explicit("jitter")   { jitter = OPSEC_JITTER_MS; }
        if !is_explicit("ldap-filter") { ldap_filter = OPSEC_LDAP_FILTER.to_string(); }
    }

    // Return all
    Options {
        domain: d.to_string(),
        username,
        password,
        hashes,
        ldapfqdn: f,
        ip,
        port,
        name_server: n.to_string(),
        path: path.to_string(),
        collection_method,
        transport,
        ldaps,
        dns_tcp,
        fqdn_resolver,
        kerberos,
        pfx,
        pfx_pass,
        crt,
        key,
        zip: z,
        verbose: v,
        ldap_filter,
        cache,
        cache_buffer_size,
        resume,
        ldap_timeout,
        smb_timeout,
        host_timeout,
        http_timeout,
        computer_expiry_days,
        workers,
        throttle,
        jitter,
        opsec,
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
        password: "not set".to_string(),
        ldapfqdn: Some(fqdn.to_string()),
        ip: None, 
        port: port,
        name_server: "127.0.0.1".to_string(),
        path: "./output".to_string(),
        collection_method: CollectionMethod::All,
        transport: Transport::Ldap,
        ldaps: ldaps,
        dns_tcp: false,
        fqdn_resolver: false,
        hashes: None,
        kerberos: true,
        pfx: None,
        pfx_pass: None,
        crt: None,
        key: None,
        zip: true,
        verbose: log::LevelFilter::Info,
        ldap_filter: "(objectClass=*)".to_string(),
        cache: false,
        cache_buffer_size: 1000,
        resume: false,
        ldap_timeout: std::time::Duration::from_secs(10),
        smb_timeout: std::time::Duration::from_secs(1),
        host_timeout: std::time::Duration::from_secs(8),
        http_timeout: std::time::Duration::from_secs(2),
        computer_expiry_days: 60,
        workers: 50,
        throttle: 0,
        jitter: 0,
        opsec: false,
    }
}

#[cfg(test)]
mod tests {
    use super::CollectionMethod::*;

    #[test]
    fn session_module_runs_for_every_method_that_makes_a_session_call() {
        // (method, srvsvc, wkssvc, registry, session module runs)
        let table = [
            (All,           true,  true,  true,  true),
            (Session,       true,  true,  true,  true),
            (RegistryOnly,  false, false, true,  true),
            (DCOnly,        false, false, false, false),
            (LdapOnly,      false, false, false, false),
            (GPOLocalGroup, false, false, false, false),
            (LocalGroup,    false, false, false, false),
            (WebClient,     false, false, false, false),
            (CARegistry,    false, false, false, false),
        ];
        for (method, srvsvc, wkssvc, registry, session) in table {
            assert_eq!(
                (method.srvsvc(), method.wkssvc(), method.registry(), method.does_session()),
                (srvsvc, wkssvc, registry, session),
                "{method:?}"
            );
        }
    }
}
