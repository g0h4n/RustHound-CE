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
//! Module path: `src/modules/adcs/esc8.rs`
//! Required Cargo dependency: `reqwest = { version = "0.12", default-features = false, features = ["blocking", "rustls-tls-ring"] }`

use crate::objects::enterpriseca::{WebEnrollmentEndpoint, WebEnrollmentResult};
use crate::utils::b64::{b64_decode, b64_encode};
use log::{debug, warn};
use reqwest::blocking::Client;
use reqwest::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use std::time::Duration;

// NTLM AvPair IDs

/// End-of-list marker in NTLM TargetInfo AvPairs.
const MV_AV_EOL: u16 = 0x0000;

/// `MsvAvChannelBindings`, present with non-zero length when EPA is required.
const MV_AV_CHANNEL_BINDINGS: u16 = 0x000A;

// Minimal NTLM Type 1 (Negotiate)

/// Anonymous NTLM Type 1 Negotiate token.
///
/// Flags encoded (little-endian `0xa2088207`):
///  NTLMSSP_NEGOTIATE_UNICODE            (0x00000001)
///  NTLMSSP_NEGOTIATE_OEM                (0x00000002)
///  NTLMSSP_REQUEST_TARGET               (0x00000004)
///  NTLMSSP_NEGOTIATE_NTLM               (0x00000200)
///  NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY (0x00080000)
///  NTLMSSP_NEGOTIATE_128                (0x20000000)
///  NTLMSSP_NEGOTIATE_56                 (0x80000000)
///
/// Domain and Workstation fields are empty; no version block.
const NTLM_NEGOTIATE: &[u8] = &[
    // Signature
    0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
    // MessageType = 1
    0x01, 0x00, 0x00, 0x00,
    // NegotiateFlags (LE 0xa2088207)
    0x07, 0x82, 0x08, 0xa2,
    // DomainNameFields: Len=0, MaxLen=0, Offset=32
    0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
    // WorkstationFields: Len=0, MaxLen=0, Offset=32
    0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
];

// Status string values matching BloodHound CE expected format.
pub const STATUS_VULNERABLE_HTTP:  &str = "Vulnerable_NtlmHttpEndpoint";
pub const STATUS_VULNERABLE_HTTPS: &str = "Vulnerable_NtlmHttpsEndpointWithoutEpa";
pub const STATUS_NOT_VULN_EPA:     &str = "NotVulnerable_EpaEnabled";
pub const STATUS_NOT_VULN_PORT:    &str = "NotVulnerable_PortInaccessible";

// Public types

/// Status of a single web-enrollment endpoint (HTTP or HTTPS).
#[derive(Debug, Clone, PartialEq)]
pub enum WebEnrollmentStatus {
    /// Endpoint not reachable, or web enrollment not installed.
    NotFound,
    /// Web enrollment is reachable and NTLM auth is available, relay possible.
    Vulnerable,
    /// Web enrollment is on HTTPS and EPA/channel binding is enforced, protected.
    Protected,
}

// Builder functions for WebEnrollmentEndpoint
// (impl on an external type would violate the orphan rule)

/// Build a WebEnrollmentEndpoint from a plain-HTTP probe result.
fn build_http_endpoint(host: &str, vulnerable: bool) -> WebEnrollmentEndpoint {
    WebEnrollmentEndpoint {
        result: Some(WebEnrollmentResult {
            url:                       format!("http://{}/certsrv/", host),
            enrollment_type:           "WebEnrollmentApplication".to_string(),
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

/// Build a WebEnrollmentEndpoint from an HTTPS probe result.
fn build_https_endpoint(host: &str, https_status: &WebEnrollmentStatus) -> WebEnrollmentEndpoint {
    let (status, https, epa) = match https_status {
        WebEnrollmentStatus::Vulnerable => (STATUS_VULNERABLE_HTTPS.to_string(), true,  false),
        WebEnrollmentStatus::Protected  => (STATUS_NOT_VULN_EPA.to_string(),     true,  true),
        WebEnrollmentStatus::NotFound   => (STATUS_NOT_VULN_PORT.to_string(),    false, false),
    };
    WebEnrollmentEndpoint {
        result: Some(WebEnrollmentResult {
            url:                       format!("https://{}/certsrv/", host),
            enrollment_type:           "WebEnrollmentApplication".to_string(),
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
    /// HTTP endpoint status.
    pub http: WebEnrollmentStatus,
    /// HTTPS endpoint status (checks EPA via NTLM Type 2 parsing).
    pub https: WebEnrollmentStatus,
    /// `true` if either endpoint is relay-able.
    pub vulnerable: bool,
    /// Both endpoints (HTTP + HTTPS), ready for JSON serialization.
    pub endpoints: Vec<WebEnrollmentEndpoint>,
}

// Public API

/// Run the full ESC8 probe against a CA host (both HTTP and HTTPS).
///
/// Returns `None` if the host is completely unreachable on both endpoints.
pub fn check_esc8(host: &str) -> Option<Esc8Result> {
    let http  = probe_http(host);
    let https = probe_https(host);

    if http == WebEnrollmentStatus::NotFound && https == WebEnrollmentStatus::NotFound {
        return None;
    }

    let vulnerable = http  == WebEnrollmentStatus::Vulnerable
        || https == WebEnrollmentStatus::Vulnerable;

    if http == WebEnrollmentStatus::Vulnerable {
        warn!(
            "ESC8 detected on {}, Web Enrollment exposed over HTTP without EPA \
             (NTLM relay possible on http://{}/certsrv/certfnsh.asp)",
            host, host
        );
    }
    if https == WebEnrollmentStatus::Vulnerable {
        warn!(
            "ESC8 detected on {}, Web Enrollment over HTTPS without Channel Binding \
             (NTLM relay possible on https://{}/certsrv/certfnsh.asp)",
            host, host
        );
    }
    if https == WebEnrollmentStatus::Protected {
        debug!("ESC8 HTTPS {}: EPA/Channel Binding enforced, protected", host);
    }

    let endpoints = vec![
        build_http_endpoint(host, http == WebEnrollmentStatus::Vulnerable),
        build_https_endpoint(host, &https),
    ];

    Some(Esc8Result {
        host: host.to_string(),
        http,
        https,
        vulnerable,
        endpoints,
    })
}

// Internal probes

/// Probe the plain-HTTP enrollment endpoint.
///
/// A `401` response carrying `WWW-Authenticate: NTLM` or `Negotiate` over HTTP
/// is sufficient to flag ESC8, HTTP provides no channel-binding protection.
fn probe_http(host: &str) -> WebEnrollmentStatus {
    let url = format!("http://{}/certsrv/certfnsh.asp", host);
    debug!("ESC8 HTTP probe: {}", url);

    let client = match Client::builder()
        .timeout(Duration::from_secs(5))
        .connect_timeout(Duration::from_secs(3))
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()
    {
        Ok(c) => c,
        Err(_) => return WebEnrollmentStatus::NotFound,
    };

    let response = match client.head(&url).send() {
        Ok(r) => r,
        Err(_) => return WebEnrollmentStatus::NotFound,
    };

    let status = response.status().as_u16();
    let has_ntlm = response
        .headers()
        .get_all(WWW_AUTHENTICATE)
        .iter()
        .any(|v| {
            let s = v.to_str().unwrap_or("").to_lowercase();
            s.starts_with("ntlm") || s.starts_with("negotiate")
        });

    debug!("ESC8 HTTP probe {}: status={} ntlm={}", host, status, has_ntlm);

    if status == 401 && has_ntlm {
        WebEnrollmentStatus::Vulnerable
    } else {
        WebEnrollmentStatus::NotFound
    }
}

/// Probe the HTTPS enrollment endpoint and check for EPA (Channel Binding).
///
/// Sends a minimal NTLM Type 1 Negotiate. If the server responds with a Type 2
/// Challenge, parses the `TargetInfo` AvPairs to check for `MsvAvChannelBindings`.
/// Absent: EPA disabled: relay possible.
fn probe_https(host: &str) -> WebEnrollmentStatus {
    let url = format!("https://{}/certsrv/certfnsh.asp", host);
    debug!("ESC8 HTTPS probe: {}", url);

    let neg_b64    = b64_encode(NTLM_NEGOTIATE);
    let auth_value = format!("NTLM {}", neg_b64);

    let client = match Client::builder()
        .timeout(Duration::from_secs(8))
        .connect_timeout(Duration::from_secs(3))
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(_) => return WebEnrollmentStatus::NotFound,
    };

    let response = match client
        .get(&url)
        .header(AUTHORIZATION, &auth_value)
        .send()
    {
        Ok(r) => r,
        Err(_) => return WebEnrollmentStatus::NotFound,
    };

    let status = response.status().as_u16();
    debug!("ESC8 HTTPS probe {}: status={}", host, status);

    if status != 401 {
        return WebEnrollmentStatus::NotFound;
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
            WebEnrollmentStatus::NotFound
        }
        Some(token) => {
            if parse_epa_channel_bindings(&token) {
                debug!("ESC8 HTTPS {}: MsvAvChannelBindings present: EPA enforced", host);
                WebEnrollmentStatus::Protected
            } else {
                debug!("ESC8 HTTPS {}: MsvAvChannelBindings absent: EPA disabled", host);
                WebEnrollmentStatus::Vulnerable
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

    // Network probe (non-routable, expected to return None)

    #[test]
    fn unreachable_host_returns_none() {
        let result = check_esc8("192.0.2.1");
        assert!(result.is_none(), "Non-routable host must return None");
    }

    // WebEnrollmentEndpoint builders

    #[test]
    fn from_http_vulnerable() {
        let ep = build_http_endpoint("ca.corp.local", true);
        let r  = ep.result.as_ref().unwrap();
        assert_eq!(r.status, STATUS_VULNERABLE_HTTP);
        assert!(r.adcs_web_enrollment_http);
        assert!(!r.adcs_web_enrollment_https);
        assert!(!r.adcs_web_enrollment_epa);
        assert!(ep.collected);
        assert!(ep.failure_reason.is_none());
    }

    #[test]
    fn from_http_not_found() {
        let ep = build_http_endpoint("ca.corp.local", false);
        let r  = ep.result.as_ref().unwrap();
        assert_eq!(r.status, STATUS_NOT_VULN_PORT);
        assert!(!r.adcs_web_enrollment_http);
    }

    #[test]
    fn from_https_vulnerable() {
        let ep = build_https_endpoint("ca.corp.local", &WebEnrollmentStatus::Vulnerable);
        let r  = ep.result.as_ref().unwrap();
        assert_eq!(r.status, STATUS_VULNERABLE_HTTPS);
        assert!(!r.adcs_web_enrollment_http);
        assert!(r.adcs_web_enrollment_https);
        assert!(!r.adcs_web_enrollment_epa);
    }

    #[test]
    fn from_https_protected() {
        let ep = build_https_endpoint("ca.corp.local", &WebEnrollmentStatus::Protected);
        let r  = ep.result.as_ref().unwrap();
        assert_eq!(r.status, STATUS_NOT_VULN_EPA);
        assert!(r.adcs_web_enrollment_https);
        assert!(r.adcs_web_enrollment_epa);
    }

    #[test]
    fn from_https_not_found() {
        let ep = build_https_endpoint("ca.corp.local", &WebEnrollmentStatus::NotFound);
        let r  = ep.result.as_ref().unwrap();
        assert_eq!(r.status, STATUS_NOT_VULN_PORT);
        assert!(!r.adcs_web_enrollment_https);
        assert!(!r.adcs_web_enrollment_epa);
    }
}