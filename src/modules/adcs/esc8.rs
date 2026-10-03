//! ESC8 scanner, Web Enrollment HTTP/HTTPS probe + EPA (Channel Binding) detection.
//!
//! Detects whether a CA exposes the `/certsrv/certfnsh.asp` endpoint over HTTP
//! (always vulnerable to NTLM relay) or over HTTPS without Extended Protection for
//! Authentication (EPA / Channel Binding), which is also vulnerable.
//!
//! The EPA check works by sending a minimal NTLM Type 1 (Negotiate) message to the
//! HTTPS endpoint and parsing the server's NTLM Type 2 (Challenge) response. If the
//! `MsvAvChannelBindings` AvPair (AvId `0x000A`) is absent from the challenge's
//! `TargetInfo`, EPA is not enforced and the endpoint is relay-able.
//!
//! This approach requires a single HTTP round-trip, no credentials, no full
//! NTLM handshake, no relay attempted.
//!
//! Three outcomes are distinguished per endpoint, matching SharpHound's JSON shape:
//!
//! | Situation                          | JSON                                               |
//! |------------------------------------|----------------------------------------------------|
//! | TCP port closed / unreachable      | `Collected: true`, `NotVulnerable_PortInaccessible` |
//! | Port open, HTTP request failed     | `Collected: false` + `FailureReason`                |
//! | Port open, status determined       | `Collected: true` + the matching status             |
//!
//! A closed port is a *result*, not a collection failure: the CA was successfully
//! determined not to expose web enrollment there. A 404 on an open port is the
//! opposite, the probe could not conclude, so it is reported as not collected.
//! The two `/certsrv/` endpoints (HTTP + HTTPS) are ALWAYS emitted, so an empty
//! `HttpEnrollmentEndpoints` array now only ever means "the module did not run".
//!
//! In addition to classic Web Enrollment, the Certificate Enrollment Web Service
//! (CES) is probed at `<CAName>_CES_<AuthType>/service.svc/CES` over both HTTP
//! and HTTPS, for each auth type in [`CES_AUTH_TYPES`]. CES is a second NTLM
//! relay surface to AD CS; HTTPS reuses the same EPA/Channel-Binding logic as
//! certsrv, and an HTTP-exposed CES is flagged outright. These endpoints carry
//! `Type: CertificateEnrollmentWebService` and are only added when the CA short
//! name is known. Ref: <https://adhdmurky.github.io/posts/post4/>
//!
//! Module path: `src/modules/adcs/esc8.rs`
//! Required Cargo dependency: `reqwest = { version = "0.12", default-features = false, features = ["blocking", "rustls-tls-ring"] }`

use crate::objects::enterpriseca::{WebEnrollmentEndpoint, WebEnrollmentResult};
use crate::utils::b64::{b64_decode, b64_encode};
use log::{debug, warn};
use reqwest::blocking::Client;
use reqwest::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

// NTLM AvPair IDs

/// End-of-list marker in NTLM TargetInfo AvPairs.
const MV_AV_EOL: u16 = 0x0000;

/// `MsvAvChannelBindings`, present with non-zero length when EPA is required.
const MV_AV_CHANNEL_BINDINGS: u16 = 0x000A;

// Timeouts

/// TCP connect timeout for the port-reachability pre-check.
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Connect timeout for the reqwest clients.
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Total request timeout, plain HTTP.
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);
/// Total request timeout, HTTPS (TLS handshake included).
const HTTPS_TIMEOUT: Duration = Duration::from_secs(8);

// Minimal NTLM Type 1 (Negotiate)

/// Anonymous NTLM Type 1 Negotiate token.
///
/// Flags encoded (little-endian `0xa0088207`):
///  NTLMSSP_NEGOTIATE_UNICODE                  (0x00000001)
///  NTLMSSP_NEGOTIATE_OEM                      (0x00000002)
///  NTLMSSP_REQUEST_TARGET                     (0x00000004)
///  NTLMSSP_NEGOTIATE_NTLM                     (0x00000200)
///  NTLMSSP_NEGOTIATE_ALWAYS_SIGN              (0x00008000)
///  NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY (0x00080000)
///  NTLMSSP_NEGOTIATE_128                      (0x20000000)
///  NTLMSSP_NEGOTIATE_56                       (0x80000000)
///
/// NEGOTIATE_VERSION (0x02000000) MUST NOT be set here: MS-NLMP §2.2.1.1
/// requires an 8-byte Version block when that flag is present, and this
/// minimal 32-byte token omits it. IIS/HTTP.sys rejects a Type 1 that claims
/// NEGOTIATE_VERSION without a Version block: it never returns a Type 2
/// challenge, so the EPA probe cannot see MsvAvChannelBindings and the CA
/// is silently reported as not ESC8-vulnerable.
///
/// Domain and Workstation fields are empty; no version block.
const NTLM_NEGOTIATE: &[u8] = &[
    // Signature
    0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
    // MessageType = 1
    0x01, 0x00, 0x00, 0x00,
    // NegotiateFlags LE 0xa0088207 (no NEGOTIATE_VERSION 0x02000000: without a Version block
    // present, IIS rejects the Type 1 as malformed and never returns a Type 2 challenge).
    0x07, 0x82, 0x08, 0xa0,
    // DomainNameFields: empty
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // WorkstationFields: empty
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// Status string values matching BloodHound CE expected format.
pub const STATUS_VULNERABLE_HTTP:  &str = "Vulnerable_NtlmHttpEndpoint";
pub const STATUS_VULNERABLE_HTTPS: &str = "Vulnerable_NtlmHttpsEndpointWithoutEpa";
pub const STATUS_NOT_VULN_EPA:     &str = "NotVulnerable_EpaEnabled";
pub const STATUS_NOT_VULN_PORT:    &str = "NotVulnerable_PortInaccessible";

/// Value of `Type` in the serialized endpoint, matching SharpHound.
const TYPE_WEB_ENROLLMENT: &str = "WebEnrollmentApplication";

/// Value of `Type` for Certificate Enrollment Web Service (CES) endpoints.
/// Not emitted by SharpHound today; lets BloodHound/analysis tell a CES relay
/// surface apart from classic `/certsrv/` web enrollment.
const TYPE_CES: &str = "CertificateEnrollmentWebService";

/// CES authentication-type suffixes to probe. The IIS virtual directory is
/// named `<SanitizedCAName>_CES_<AuthType>`. Microsoft's native auth types are
/// `Kerberos`, `UserName` and `ClientCertificate`; `NTLM` is included because
/// it is the relay-relevant variant seen in the wild (see module ref).
const CES_AUTH_TYPES: &[&str] = &["Kerberos", "NTLM"];

/// URL reported in the JSON, kept identical to SharpHound for ingest parity.
/// The probe itself targets `certfnsh.asp` under this path.
fn display_url(scheme: &str, host: &str) -> String {
    format!("{}://{}/certsrv/", scheme, host)
}

/// URL actually requested by the probes.
fn probe_url(scheme: &str, host: &str) -> String {
    format!("{}://{}/certsrv/certfnsh.asp", scheme, host)
}

/// CES endpoint URL. Display and probe target are identical: the WSTEP
/// `service.svc/CES` path is what the NTLM/EPA probe hits directly.
///
/// `ca` is the sanitized CA short name. This v1 passes the CA common name
/// through unchanged, which is correct for names made of the safe character
/// set. Names containing spaces or other characters require the MS-WCCE
/// sanitization (`!XXXX` hex encoding) that is not yet implemented here.
fn ces_url(scheme: &str, host: &str, ca: &str, auth: &str) -> String {
    format!("{}://{}/{}_CES_{}/service.svc/CES", scheme, host, ca, auth)
}

// Public types

/// Status of a single web-enrollment endpoint (HTTP or HTTPS).
#[derive(Debug, Clone, PartialEq)]
pub enum WebEnrollmentStatus {
    /// Endpoint answered but web enrollment is not exposed, or NTLM not offered.
    NotFound,
    /// Web enrollment is reachable and NTLM auth is available, relay possible.
    Vulnerable,
    /// Web enrollment is on HTTPS and EPA/channel binding is enforced, protected.
    Protected,
}

/// Outcome of a single probe, mapped 1:1 onto the three JSON shapes.
#[derive(Debug, Clone, PartialEq)]
pub enum ProbeOutcome {
    /// The port answered and a status could be determined.
    Reached(WebEnrollmentStatus),
    /// TCP connection refused, filtered or timed out. This is a result.
    PortClosed,
    /// Port open but the HTTP exchange failed (404, TLS error, timeout...).
    Failed(String),
}

/// Reduce an outcome to a status; anything but `Reached` counts as not found.
fn outcome_status(outcome: &ProbeOutcome) -> WebEnrollmentStatus {
    match outcome {
        ProbeOutcome::Reached(status) => status.clone(),
        _ => WebEnrollmentStatus::NotFound,
    }
}

// Builder functions for WebEnrollmentEndpoint
// (impl on an external type would violate the orphan rule)

/// Shared tail of both builders: a closed port and a failed request.
fn build_non_result(
    url: String,
    enrollment_type: &str,
    outcome: &ProbeOutcome,
) -> Option<WebEnrollmentEndpoint> {
    match outcome {
        ProbeOutcome::PortClosed => Some(WebEnrollmentEndpoint {
            result: Some(WebEnrollmentResult {
                url,
                enrollment_type:           enrollment_type.to_string(),
                status:                    STATUS_NOT_VULN_PORT.to_string(),
                adcs_web_enrollment_http:  false,
                adcs_web_enrollment_https: false,
                adcs_web_enrollment_epa:   false,
            }),
            collected:      true,
            failure_reason: None,
        }),
        ProbeOutcome::Failed(reason) => Some(WebEnrollmentEndpoint {
            result:         None,
            collected:      false,
            failure_reason: Some(reason.clone()),
        }),
        ProbeOutcome::Reached(_) => None,
    }
}

/// Build a WebEnrollmentEndpoint from a plain-HTTP probe outcome.
/// `url` is the value reported in the JSON; `enrollment_type` is the `Type`.
fn build_http_endpoint(
    url: String,
    enrollment_type: &str,
    outcome: &ProbeOutcome,
) -> WebEnrollmentEndpoint {
    if let Some(ep) = build_non_result(url.clone(), enrollment_type, outcome) {
        return ep;
    }

    let vulnerable = outcome_status(outcome) == WebEnrollmentStatus::Vulnerable;

    WebEnrollmentEndpoint {
        result: Some(WebEnrollmentResult {
            url,
            enrollment_type:           enrollment_type.to_string(),
            status: if vulnerable {
                STATUS_VULNERABLE_HTTP.to_string()
            } else {
                STATUS_NOT_VULN_PORT.to_string()
            },
            adcs_web_enrollment_http:  vulnerable,
            adcs_web_enrollment_https: false,
            adcs_web_enrollment_epa:   false,
        }),
        collected:      true,
        failure_reason: None,
    }
}

/// Build a WebEnrollmentEndpoint from an HTTPS probe outcome.
/// `url` is the value reported in the JSON; `enrollment_type` is the `Type`.
fn build_https_endpoint(
    url: String,
    enrollment_type: &str,
    outcome: &ProbeOutcome,
) -> WebEnrollmentEndpoint {
    if let Some(ep) = build_non_result(url.clone(), enrollment_type, outcome) {
        return ep;
    }

    let (status, https, epa) = match outcome_status(outcome) {
        WebEnrollmentStatus::Vulnerable => (STATUS_VULNERABLE_HTTPS.to_string(), true,  false),
        WebEnrollmentStatus::Protected  => (STATUS_NOT_VULN_EPA.to_string(),     true,  true),
        WebEnrollmentStatus::NotFound   => (STATUS_NOT_VULN_PORT.to_string(),    false, false),
    };

    WebEnrollmentEndpoint {
        result: Some(WebEnrollmentResult {
            url,
            enrollment_type:           enrollment_type.to_string(),
            status,
            adcs_web_enrollment_http:  false,
            adcs_web_enrollment_https: https,
            adcs_web_enrollment_epa:   epa,
        }),
        collected:      true,
        failure_reason: None,
    }
}

/// Full ESC8 probe result for a CA host.
#[derive(Debug, Clone)]
pub struct Esc8Result {
    pub host: String,
    /// HTTP endpoint status (a closed port or failed request collapses to `NotFound`).
    pub http: WebEnrollmentStatus,
    /// HTTPS endpoint status (checks EPA via NTLM Type 2 parsing).
    pub https: WebEnrollmentStatus,
    /// `true` if either endpoint is relay-able.
    pub vulnerable: bool,
    /// Both endpoints (HTTP + HTTPS), ready for JSON serialization.
    /// Never empty: two entries are always produced.
    pub endpoints: Vec<WebEnrollmentEndpoint>,
}

// Public API

/// Run the full ESC8 probe against a CA host.
///
/// Probes classic Web Enrollment (`/certsrv/`) over HTTP and HTTPS, then each
/// CES virtual directory (`<ca_name>_CES_<AuthType>/service.svc/CES`) over
/// HTTPS, which is the CES default. Always returns at least the two certsrv
/// endpoints, so the caller can tell "probed, nothing found" apart from
/// "never probed". CES endpoints are added only when `ca_name` is non-empty
/// (there is no vdir path to build otherwise).
pub fn check_esc8(host: &str, ca_name: &str) -> Esc8Result {
    let http_outcome  = probe_http(host, &probe_url("http", host));
    let https_outcome = probe_https(host, &probe_url("https", host));

    let http  = outcome_status(&http_outcome);
    let https = outcome_status(&https_outcome);

    let mut vulnerable = http  == WebEnrollmentStatus::Vulnerable
        || https == WebEnrollmentStatus::Vulnerable;

    if http == WebEnrollmentStatus::Vulnerable {
        warn!(
            "ESC8 detected on {}, Web Enrollment exposed over HTTP without EPA \
             (NTLM relay possible on {})",
            host,
            probe_url("http", host)
        );
    }
    if https == WebEnrollmentStatus::Vulnerable {
        warn!(
            "ESC8 detected on {}, Web Enrollment over HTTPS without Channel Binding \
             (NTLM relay possible on {})",
            host,
            probe_url("https", host)
        );
    }
    if https == WebEnrollmentStatus::Protected {
        debug!("ESC8 HTTPS {}: EPA/Channel Binding enforced, protected", host);
    }
    if let ProbeOutcome::Failed(ref reason) = http_outcome {
        debug!("ESC8 HTTP {} not collected: {}", host, reason);
    }
    if let ProbeOutcome::Failed(ref reason) = https_outcome {
        debug!("ESC8 HTTPS {} not collected: {}", host, reason);
    }

    let mut endpoints = vec![
        build_http_endpoint(display_url("http", host), TYPE_WEB_ENROLLMENT, &http_outcome),
        build_https_endpoint(display_url("https", host), TYPE_WEB_ENROLLMENT, &https_outcome),
    ];

    // CES probe. CES is normally HTTPS-only (Microsoft requires SSL), but it is
    // probed over both schemes for parity with certsrv: an HTTP-exposed CES is a
    // misconfiguration that is trivially relayable (no channel binding), and
    // probing HTTP also tells "vdir absent" (404) apart from "port inaccessible"
    // when 443 is closed. The EPA/Channel-Binding logic over HTTPS is identical
    // to the certsrv HTTPS probe.
    if ca_name.is_empty() {
        debug!("ESC8 CES probe skipped on {}: empty CA name", host);
    } else {
        for auth in CES_AUTH_TYPES {
            // HTTP (rare; relay-able outright if NTLM is offered there).
            let http_url     = ces_url("http", host, ca_name, auth);
            let http_outcome = probe_http(host, &http_url);
            if outcome_status(&http_outcome) == WebEnrollmentStatus::Vulnerable {
                vulnerable = true;
                warn!(
                    "ESC8 detected on {}, CES ({}) exposed over HTTP without EPA \
                     (NTLM relay possible on {})",
                    host, auth, http_url
                );
            }
            if let ProbeOutcome::Failed(ref reason) = http_outcome {
                debug!("ESC8 CES HTTP {} ({}) not collected: {}", host, auth, reason);
            }
            endpoints.push(build_http_endpoint(http_url, TYPE_CES, &http_outcome));

            // HTTPS (CES default): check EPA / Channel Binding.
            let https_url     = ces_url("https", host, ca_name, auth);
            let https_outcome = probe_https(host, &https_url);
            if outcome_status(&https_outcome) == WebEnrollmentStatus::Vulnerable {
                vulnerable = true;
                warn!(
                    "ESC8 detected on {}, CES ({}) over HTTPS without Channel Binding \
                     (NTLM relay possible on {})",
                    host, auth, https_url
                );
            }
            if let ProbeOutcome::Failed(ref reason) = https_outcome {
                debug!("ESC8 CES HTTPS {} ({}) not collected: {}", host, auth, reason);
            }
            endpoints.push(build_https_endpoint(https_url, TYPE_CES, &https_outcome));
        }
    }

    Esc8Result {
        host: host.to_string(),
        http,
        https,
        vulnerable,
        endpoints,
    }
}

// Port reachability

/// Result of the TCP pre-check.
enum PortState {
    /// At least one resolved address accepted the connection.
    Open,
    /// Every resolved address refused, filtered or timed out.
    Closed,
    /// The name could not be resolved at all.
    Unresolved(String),
}

/// Test whether `host:port` accepts a TCP connection.
///
/// Run before the HTTP request so that "nothing is listening" can be reported as
/// `NotVulnerable_PortInaccessible` rather than as a transport failure.
fn check_port(host: &str, port: u16) -> PortState {
    let addrs = match (host, port).to_socket_addrs() {
        Ok(a) => a.collect::<Vec<_>>(),
        Err(e) => {
            return PortState::Unresolved(format!(
                "DNS resolution failed for {}:{}: {}",
                host, port, e
            ));
        }
    };

    if addrs.is_empty() {
        return PortState::Unresolved(format!("no address resolved for {}:{}", host, port));
    }

    for addr in &addrs {
        match TcpStream::connect_timeout(addr, TCP_CONNECT_TIMEOUT) {
            Ok(_) => {
                debug!("ESC8 port check {}:{} open ({})", host, port, addr);
                return PortState::Open;
            }
            Err(e) => debug!("ESC8 port check {} unreachable: {}", addr, e),
        }
    }

    PortState::Closed
}

// Internal probes

/// Probe the plain-HTTP enrollment endpoint.
///
/// A `401` response carrying `WWW-Authenticate: NTLM` or `Negotiate` over HTTP
/// is sufficient to flag ESC8, HTTP provides no channel-binding protection.
///
/// A `404` means IIS is up but web enrollment is not installed: the probe cannot
/// conclude, so it is reported as not collected, like SharpHound does.
fn probe_http(host: &str, url: &str) -> ProbeOutcome {
    debug!("ESC8 HTTP probe: {}", url);

    match check_port(host, 80) {
        PortState::Open => {}
        PortState::Closed => return ProbeOutcome::PortClosed,
        PortState::Unresolved(reason) => return ProbeOutcome::Failed(reason),
    }

    let client = match Client::builder()
        .timeout(HTTP_TIMEOUT)
        .connect_timeout(HTTP_CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return ProbeOutcome::Failed(format!("failed to build HTTP client for {}: {}", url, e));
        }
    };

    let response = match client.head(url).send() {
        Ok(r) => r,
        Err(e) => {
            return ProbeOutcome::Failed(format!("HTTP request to {} failed: {}", url, e));
        }
    };

    let status = response.status();
    let code   = status.as_u16();
    let has_ntlm = response
        .headers()
        .get_all(WWW_AUTHENTICATE)
        .iter()
        .any(|v| {
            let s = v.to_str().unwrap_or("").to_lowercase();
            s.starts_with("ntlm") || s.starts_with("negotiate")
        });

    debug!("ESC8 HTTP probe {}: status={} ntlm={}", host, code, has_ntlm);

    if code == 401 {
        return if has_ntlm {
            ProbeOutcome::Reached(WebEnrollmentStatus::Vulnerable)
        } else {
            // Authentication required but NTLM is not offered (Kerberos-only).
            ProbeOutcome::Reached(WebEnrollmentStatus::NotFound)
        };
    }

    if status.is_success() || status.is_redirection() {
        // Endpoint answers without requiring authentication: nothing to relay.
        return ProbeOutcome::Reached(WebEnrollmentStatus::NotFound);
    }

    ProbeOutcome::Failed(format!(
        "Response status code does not indicate success: {} ({}) for {}",
        code,
        status.canonical_reason().unwrap_or("Unknown"),
        url
    ))
}

/// Probe the HTTPS enrollment endpoint and check for EPA (Channel Binding).
///
/// Sends a minimal NTLM Type 1 Negotiate. If the server responds with a Type 2
/// Challenge, parses the `TargetInfo` AvPairs to check for `MsvAvChannelBindings`.
/// Absent: EPA disabled: relay possible.
fn probe_https(host: &str, url: &str) -> ProbeOutcome {
    debug!("ESC8 HTTPS probe: {}", url);

    match check_port(host, 443) {
        PortState::Open => {}
        PortState::Closed => return ProbeOutcome::PortClosed,
        PortState::Unresolved(reason) => return ProbeOutcome::Failed(reason),
    }

    let neg_b64    = b64_encode(NTLM_NEGOTIATE);
    let auth_value = format!("NTLM {}", neg_b64);

    let client = match Client::builder()
        .timeout(HTTPS_TIMEOUT)
        .connect_timeout(HTTP_CONNECT_TIMEOUT)
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return ProbeOutcome::Failed(format!("failed to build HTTPS client for {}: {}", url, e));
        }
    };

    let response = match client.get(url).header(AUTHORIZATION, &auth_value).send() {
        Ok(r) => r,
        Err(e) => {
            return ProbeOutcome::Failed(format!("HTTPS request to {} failed: {}", url, e));
        }
    };

    let status = response.status();
    let code   = status.as_u16();
    debug!("ESC8 HTTPS probe {}: status={}", host, code);

    if code != 401 {
        if status.is_success() || status.is_redirection() {
            return ProbeOutcome::Reached(WebEnrollmentStatus::NotFound);
        }
        return ProbeOutcome::Failed(format!(
            "Response status code does not indicate success: {} ({}) for {}",
            code,
            status.canonical_reason().unwrap_or("Unknown"),
            url
        ));
    }

    // Find the NTLM Type 2 Challenge token in WWW-Authenticate headers
    let challenge_token = response
        .headers()
        .get_all(WWW_AUTHENTICATE)
        .iter()
        .find_map(|v| {
            let s = v.to_str().unwrap_or("");
            let lower = s.to_ascii_lowercase();
            if let Some(rest) = lower.strip_prefix("ntlm ") {
                let token_b64 = rest.trim();
                if token_b64.len() > 16 {
                    let orig = s["ntlm ".len()..].trim();
                    return b64_decode(orig);
                }
            }
            None
        });

    match challenge_token {
        None => {
            debug!(
                "ESC8 HTTPS {}: no NTLM challenge received (Kerberos-only or not installed)",
                host
            );
            ProbeOutcome::Reached(WebEnrollmentStatus::NotFound)
        }
        Some(token) => {
            if parse_epa_channel_bindings(&token) {
                debug!("ESC8 HTTPS {}: MsvAvChannelBindings present: EPA enforced", host);
                ProbeOutcome::Reached(WebEnrollmentStatus::Protected)
            } else {
                debug!("ESC8 HTTPS {}: MsvAvChannelBindings absent: EPA disabled", host);
                ProbeOutcome::Reached(WebEnrollmentStatus::Vulnerable)
            }
        }
    }
}

// NTLM Type 2 / EPA parsing

/// Parse an NTLM Type 2 (Challenge) token and return `true` if
/// `MsvAvChannelBindings` (AvId `0x000A`) is present with a **non-zero** length.
/// <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/34a9417d-7cc0-43b0-b61c-1f19740df66f>
///
/// NTLM Type 2 layout (all little-endian):
///
/// | Offset | Size | Field               |
/// |--------|------|---------------------|
/// |  0     |  8   | Signature           |
/// |  8     |  4   | MessageType = 2     |
/// | 12     |  8   | TargetNameFields    |
/// | 20     |  4   | NegotiateFlags      |
/// | 24     |  8   | ServerChallenge     |
/// | 32     |  8   | Reserved            |
/// | 40     |  8   | TargetInfoFields    |
/// | 48     |  8   | Version (optional)  |
/// | 56+    |  …   | Payload             |
///
/// AvPair layout: `AvId u16 | AvLen u16 | AvValue [u8; AvLen]`
pub fn parse_epa_channel_bindings(token: &[u8]) -> bool {
    if token.len() < 48 {
        debug!("NTLM token too short ({} bytes), cannot parse as Type 2", token.len());
        return false;
    }

    if &token[0..8] != b"NTLMSSP\0" {
        debug!("NTLM signature mismatch");
        return false;
    }

    let msg_type = u32::from_le_bytes([token[8], token[9], token[10], token[11]]);
    if msg_type != 2 {
        debug!("Not a Type 2 message (MessageType={})", msg_type);
        return false;
    }

    let ti_len = u16::from_le_bytes([token[40], token[41]]) as usize;
    let ti_off = u32::from_le_bytes([token[44], token[45], token[46], token[47]]) as usize;

    if ti_len == 0 {
        debug!("TargetInfo is empty, no AvPairs to inspect");
        return false;
    }
    if token.len() < ti_off.saturating_add(ti_len) {
        debug!(
            "TargetInfo out of bounds (off={}, len={}, token_len={})",
            ti_off, ti_len, token.len()
        );
        return false;
    }

    let avpairs = &token[ti_off..ti_off + ti_len];
    debug!("Parsing {} bytes of AvPairs", avpairs.len());

    let mut i = 0;
    while i + 4 <= avpairs.len() {
        let av_id  = u16::from_le_bytes([avpairs[i],     avpairs[i + 1]]);
        let av_len = u16::from_le_bytes([avpairs[i + 2], avpairs[i + 3]]) as usize;

        match av_id {
            MV_AV_EOL => {
                debug!("MsvAvEOL reached");
                break;
            }
            MV_AV_CHANNEL_BINDINGS => {
                debug!("MsvAvChannelBindings found (av_len={})", av_len);
                return av_len > 0;
            }
            other => {
                debug!("AvPair id=0x{:04x} len={}, skipping", other, av_len);
                i += 4 + av_len;
            }
        }
    }

    false
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    // Test helpers

    fn build_type2(avpairs: &[u8]) -> Vec<u8> {
        let mut t = Vec::new();
        t.extend_from_slice(b"NTLMSSP\0");
        t.extend_from_slice(&2u32.to_le_bytes());
        t.extend_from_slice(&0u16.to_le_bytes());
        t.extend_from_slice(&0u16.to_le_bytes());
        t.extend_from_slice(&56u32.to_le_bytes());
        t.extend_from_slice(&0u32.to_le_bytes());
        t.extend_from_slice(&[0x01u8; 8]);
        t.extend_from_slice(&[0u8; 8]);
        let ti_len = avpairs.len() as u16;
        t.extend_from_slice(&ti_len.to_le_bytes());
        t.extend_from_slice(&ti_len.to_le_bytes());
        t.extend_from_slice(&56u32.to_le_bytes());
        t.extend_from_slice(&[0u8; 8]);
        t.extend_from_slice(avpairs);
        t
    }

    fn avpairs_with_channel_bindings(value: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&MV_AV_CHANNEL_BINDINGS.to_le_bytes());
        p.extend_from_slice(&(value.len() as u16).to_le_bytes());
        p.extend_from_slice(value);
        p.extend_from_slice(&MV_AV_EOL.to_le_bytes());
        p.extend_from_slice(&0u16.to_le_bytes());
        p
    }

    fn avpairs_without_channel_bindings() -> Vec<u8> {
        let name: Vec<u8> = "SERVER"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let mut p = Vec::new();
        p.extend_from_slice(&0x0001u16.to_le_bytes());
        p.extend_from_slice(&(name.len() as u16).to_le_bytes());
        p.extend_from_slice(&name);
        p.extend_from_slice(&MV_AV_EOL.to_le_bytes());
        p.extend_from_slice(&0u16.to_le_bytes());
        p
    }

    // parse_epa_channel_bindings

    #[test]
    fn epa_present_with_non_zero_value() {
        let cbt = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
                   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let token = build_type2(&avpairs_with_channel_bindings(&cbt));
        assert!(parse_epa_channel_bindings(&token));
    }

    #[test]
    fn epa_present_but_zero_length() {
        let token = build_type2(&avpairs_with_channel_bindings(&[]));
        assert!(!parse_epa_channel_bindings(&token));
    }

    #[test]
    fn epa_absent_from_avpairs() {
        let token = build_type2(&avpairs_without_channel_bindings());
        assert!(!parse_epa_channel_bindings(&token));
    }

    #[test]
    fn epa_multiple_avpairs_with_channel_bindings_last() {
        let name: Vec<u8> = "DC01"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let cbt = [0xAA, 0xBB, 0xCC, 0xDD];
        let mut avpairs = Vec::new();
        avpairs.extend_from_slice(&0x0001u16.to_le_bytes());
        avpairs.extend_from_slice(&(name.len() as u16).to_le_bytes());
        avpairs.extend_from_slice(&name);
        avpairs.extend_from_slice(&MV_AV_CHANNEL_BINDINGS.to_le_bytes());
        avpairs.extend_from_slice(&(cbt.len() as u16).to_le_bytes());
        avpairs.extend_from_slice(&cbt);
        avpairs.extend_from_slice(&MV_AV_EOL.to_le_bytes());
        avpairs.extend_from_slice(&0u16.to_le_bytes());
        let token = build_type2(&avpairs);
        assert!(parse_epa_channel_bindings(&token));
    }

    #[test]
    fn epa_empty_avpairs() {
        let token = build_type2(&[]);
        assert!(!parse_epa_channel_bindings(&token));
    }

    // Structural validation

    #[test]
    fn token_too_short_returns_false() {
        assert!(!parse_epa_channel_bindings(&[0u8; 10]));
        assert!(!parse_epa_channel_bindings(&[]));
    }

    #[test]
    fn invalid_signature_returns_false() {
        let mut token = build_type2(&avpairs_without_channel_bindings());
        token[0] = 0xFF;
        assert!(!parse_epa_channel_bindings(&token));
    }

    #[test]
    fn wrong_message_type_returns_false() {
        let mut token = build_type2(&avpairs_without_channel_bindings());
        token[8]  = 0x01;
        token[9]  = 0x00;
        token[10] = 0x00;
        token[11] = 0x00;
        assert!(!parse_epa_channel_bindings(&token));
    }

    #[test]
    fn target_info_offset_out_of_bounds_returns_false() {
        let avpairs = avpairs_without_channel_bindings();
        let mut token = build_type2(&avpairs);
        let bad_offset = (token.len() + 1024) as u32;
        token[44..48].copy_from_slice(&bad_offset.to_le_bytes());
        assert!(!parse_epa_channel_bindings(&token));
    }

    // Base64 helpers

    #[test]
    fn base64_roundtrip_ntlm_negotiate() {
        let encoded = b64_encode(NTLM_NEGOTIATE);
        let decoded = b64_decode(&encoded).expect("base64_decode should succeed");
        assert_eq!(NTLM_NEGOTIATE, decoded.as_slice());
    }

    #[test]
    fn base64_known_vector() {
        assert_eq!(b64_encode(b"Man"), "TWFu");
        assert_eq!(b64_decode("TWFu"), Some(b"Man".to_vec()));
    }

    #[test]
    fn base64_with_padding() {
        assert_eq!(b64_encode(b"Ma"), "TWE=");
        assert_eq!(b64_decode("TWE="), Some(b"Ma".to_vec()));
        assert_eq!(b64_encode(b"M"), "TQ==");
        assert_eq!(b64_decode("TQ=="), Some(b"M".to_vec()));
    }

    #[test]
    fn base64_decode_invalid_char_returns_none() {
        assert_eq!(b64_decode("TQ!Q"), None);
    }

    #[test]
    fn base64_decode_empty_input() {
        assert_eq!(b64_decode(""), Some(vec![]));
    }

    // URL helpers

    #[test]
    fn urls_match_sharphound_shape() {
        assert_eq!(display_url("http", "ca.corp.local"), "http://ca.corp.local/certsrv/");
        assert_eq!(
            probe_url("https", "ca.corp.local"),
            "https://ca.corp.local/certsrv/certfnsh.asp"
        );
    }

    #[test]
    fn ces_url_shape() {
        assert_eq!(
            ces_url("https", "ca.corp.local", "CORP-CA", "Kerberos"),
            "https://ca.corp.local/CORP-CA_CES_Kerberos/service.svc/CES"
        );
        assert_eq!(
            ces_url("https", "ca.corp.local", "CORP-CA", "NTLM"),
            "https://ca.corp.local/CORP-CA_CES_NTLM/service.svc/CES"
        );
    }

    // Network probe (non-routable host)

    /// Regression test for the empty `HttpEnrollmentEndpoints` bug: an
    /// unreachable host must still produce two endpoints, and a closed port is a
    /// result (`Collected: true`), not a collection failure.
    #[test]
    fn unreachable_host_reports_all_inaccessible_endpoints() {
        // 2 certsrv (HTTP + HTTPS) + HTTP + HTTPS CES endpoint per auth type.
        let expected = 2 + 2 * CES_AUTH_TYPES.len();
        let result = check_esc8("192.0.2.1", "CORP-CA");

        assert_eq!(result.endpoints.len(), expected, "every endpoint must be reported");
        assert!(!result.vulnerable, "non-routable host must not be flagged");
        assert_eq!(result.http, WebEnrollmentStatus::NotFound);
        assert_eq!(result.https, WebEnrollmentStatus::NotFound);

        for ep in &result.endpoints {
            assert!(ep.collected, "a closed port is collected data");
            assert!(ep.failure_reason.is_none());
            assert_eq!(ep.result.as_ref().unwrap().status, STATUS_NOT_VULN_PORT);
        }

        // CES endpoints are present and carry the CES type + path.
        let ces: Vec<_> = result
            .endpoints
            .iter()
            .filter_map(|e| e.result.as_ref())
            .filter(|r| r.enrollment_type == TYPE_CES)
            .collect();
        assert_eq!(ces.len(), 2 * CES_AUTH_TYPES.len());
        assert!(ces.iter().all(|r| r.url.contains("_CES_") && r.url.ends_with("/service.svc/CES")));
    }

    /// With no CA name there is no vdir path to build: only the two certsrv
    /// endpoints are emitted, no CES.
    #[test]
    fn empty_ca_name_skips_ces() {
        let result = check_esc8("192.0.2.1", "");
        assert_eq!(result.endpoints.len(), 2);
        assert!(result
            .endpoints
            .iter()
            .filter_map(|e| e.result.as_ref())
            .all(|r| r.enrollment_type == TYPE_WEB_ENROLLMENT));
    }

    // WebEnrollmentEndpoint builders

    #[test]
    fn from_http_vulnerable() {
        let ep = build_http_endpoint(
            display_url("http", "ca.corp.local"),
            TYPE_WEB_ENROLLMENT,
            &ProbeOutcome::Reached(WebEnrollmentStatus::Vulnerable),
        );
        let r = ep.result.as_ref().unwrap();
        assert_eq!(r.url, "http://ca.corp.local/certsrv/");
        assert_eq!(r.enrollment_type, TYPE_WEB_ENROLLMENT);
        assert_eq!(r.status, STATUS_VULNERABLE_HTTP);
        assert!(r.adcs_web_enrollment_http);
        assert!(!r.adcs_web_enrollment_https);
        assert!(!r.adcs_web_enrollment_epa);
        assert!(ep.collected);
        assert!(ep.failure_reason.is_none());
    }

    #[test]
    fn from_http_reached_but_not_exposed() {
        let ep = build_http_endpoint(
            display_url("http", "ca.corp.local"),
            TYPE_WEB_ENROLLMENT,
            &ProbeOutcome::Reached(WebEnrollmentStatus::NotFound),
        );
        let r = ep.result.as_ref().unwrap();
        assert_eq!(r.status, STATUS_NOT_VULN_PORT);
        assert!(!r.adcs_web_enrollment_http);
        assert!(ep.collected);
    }

    /// Port 80 closed: reported as a result, mirroring SharpHound.
    #[test]
    fn from_http_port_closed() {
        let ep = build_http_endpoint(
            display_url("http", "ca.corp.local"),
            TYPE_WEB_ENROLLMENT,
            &ProbeOutcome::PortClosed,
        );
        let r = ep.result.as_ref().unwrap();
        assert_eq!(r.status, STATUS_NOT_VULN_PORT);
        assert!(ep.collected);
        assert!(ep.failure_reason.is_none());
    }

    /// Port open but IIS answered 404: web enrollment not installed, the probe
    /// could not conclude, so nothing is collected.
    #[test]
    fn from_http_request_failed() {
        let ep = build_http_endpoint(
            display_url("http", "ca.corp.local"),
            TYPE_WEB_ENROLLMENT,
            &ProbeOutcome::Failed("Response status code does not indicate success: 404".into()),
        );
        assert!(ep.result.is_none());
        assert!(!ep.collected);
        assert!(ep.failure_reason.as_ref().unwrap().contains("404"));
    }

    #[test]
    fn from_https_vulnerable() {
        let ep = build_https_endpoint(
            display_url("https", "ca.corp.local"),
            TYPE_WEB_ENROLLMENT,
            &ProbeOutcome::Reached(WebEnrollmentStatus::Vulnerable),
        );
        let r = ep.result.as_ref().unwrap();
        assert_eq!(r.url, "https://ca.corp.local/certsrv/");
        assert_eq!(r.status, STATUS_VULNERABLE_HTTPS);
        assert!(!r.adcs_web_enrollment_http);
        assert!(r.adcs_web_enrollment_https);
        assert!(!r.adcs_web_enrollment_epa);
    }

    #[test]
    fn from_https_protected() {
        let ep = build_https_endpoint(
            display_url("https", "ca.corp.local"),
            TYPE_WEB_ENROLLMENT,
            &ProbeOutcome::Reached(WebEnrollmentStatus::Protected),
        );
        let r = ep.result.as_ref().unwrap();
        assert_eq!(r.status, STATUS_NOT_VULN_EPA);
        assert!(r.adcs_web_enrollment_https);
        assert!(r.adcs_web_enrollment_epa);
    }

    #[test]
    fn from_https_port_closed() {
        let ep = build_https_endpoint(
            display_url("https", "ca.corp.local"),
            TYPE_WEB_ENROLLMENT,
            &ProbeOutcome::PortClosed,
        );
        let r = ep.result.as_ref().unwrap();
        assert_eq!(r.status, STATUS_NOT_VULN_PORT);
        assert!(!r.adcs_web_enrollment_https);
        assert!(!r.adcs_web_enrollment_epa);
        assert!(ep.collected);
    }

    #[test]
    fn from_https_request_failed() {
        let ep = build_https_endpoint(
            display_url("https", "ca.corp.local"),
            TYPE_WEB_ENROLLMENT,
            &ProbeOutcome::Failed("TLS handshake failed".into()),
        );
        assert!(ep.result.is_none());
        assert!(!ep.collected);
        assert!(ep.failure_reason.as_ref().unwrap().contains("TLS handshake failed"));
    }
}