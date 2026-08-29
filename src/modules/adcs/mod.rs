//! ADCS active modules: ESC8 web enrollment probe.
//!
//! This module exposes `probe_enterpriseca_esc8`, the only public entry point.
//! It is called from `run_modules` after LDAP collection is complete,
//! once per EnterpriseCA object, in parallel via rayon.

pub mod esc8;

use crate::modules::adcs::esc8::{check_esc8, Esc8Result, WebEnrollmentStatus};

// Public result type

/// ESC8 probe data, ready to be injected into EnterpriseCA properties and fields.
pub struct Esc8Data {
    /// True if any web enrollment endpoint (HTTP or HTTPS) is reachable.
    pub webenrollenabled: bool,
    /// True if the plain-HTTP endpoint responded with NTLM auth (always relay-able).
    pub webenrollhttpenabled: bool,
    /// True if an HTTPS endpoint is reachable (regardless of EPA status).
    pub webenrollhttpsenabled: bool,
    /// EPA status on the HTTPS endpoint: "enabled", "disabled", "notdetected".
    pub webenrollhttpsepastatus: String,
    /// HTTP URLs that are vulnerable (populated only when webenrollhttpenabled).
    pub http_enrollment_endpoints: Vec<String>,
    /// HTTPS URLs that were found (populated when webenrollhttpsenabled).
    pub https_enrollment_endpoints: Vec<String>,
}

impl Default for Esc8Data {
    fn default() -> Self {
        Self {
            webenrollenabled:           false,
            webenrollhttpenabled:       false,
            webenrollhttpsenabled:      false,
            webenrollhttpsepastatus:    "notdetected".to_string(),
            http_enrollment_endpoints:  vec![],
            https_enrollment_endpoints: vec![],
        }
    }
}

impl From<Esc8Result> for Esc8Data {
    fn from(r: Esc8Result) -> Self {
        let webenrollhttpenabled  = r.http  == WebEnrollmentStatus::Vulnerable;
        let webenrollhttpsenabled = r.https != WebEnrollmentStatus::NotFound;

        let webenrollhttpsepastatus = match r.https {
            WebEnrollmentStatus::Protected  => "enabled".to_string(),
            WebEnrollmentStatus::Vulnerable => "disabled".to_string(),
            WebEnrollmentStatus::NotFound   => "notdetected".to_string(),
        };

        let http_enrollment_endpoints = if webenrollhttpenabled {
            vec![format!("http://{}/certsrv/", r.host)]
        } else {
            vec![]
        };

        let https_enrollment_endpoints = if webenrollhttpsenabled {
            vec![format!("https://{}/certsrv/", r.host)]
        } else {
            vec![]
        };

        Self {
            webenrollenabled: webenrollhttpenabled || webenrollhttpsenabled,
            webenrollhttpenabled,
            webenrollhttpsenabled,
            webenrollhttpsepastatus,
            http_enrollment_endpoints,
            https_enrollment_endpoints,
        }
    }
}

// Public API

/// Probe web enrollment endpoints for a single Enterprise CA.
///
/// Returns default (all false / empty) if `dns_host` is empty or unreachable.
/// The DCOnly guard is handled by the caller (`run_modules`).
pub fn probe_enterpriseca_esc8(dns_host: &str) -> Esc8Data {
    if dns_host.is_empty() {
        return Esc8Data::default();
    }
    match check_esc8(dns_host) {
        Some(result) => Esc8Data::from(result),
        None         => Esc8Data::default(),
    }
}