//! ADCS active modules, ESC8 web enrollment probe.
//!
//! Exposes `probe_enterpriseca_esc8`, called from `run_modules` after LDAP
//! collection, once per EnterpriseCA, in parallel via rayon.

pub mod esc8;

use crate::modules::adcs::esc8::{check_esc8, Esc8Result};
use crate::objects::enterpriseca::WebEnrollmentEndpoint;

// Public result type

/// ESC8 probe data ready to inject into EnterpriseCA.
pub struct Esc8Data {
    pub http_enrollment_endpoints: Vec<WebEnrollmentEndpoint>,
}

impl Default for Esc8Data {
    fn default() -> Self {
        Self { http_enrollment_endpoints: vec![] }
    }
}

impl From<Esc8Result> for Esc8Data {
    fn from(r: Esc8Result) -> Self {
        Self { http_enrollment_endpoints: r.endpoints }
    }
}

// Public API

/// Probe web enrollment endpoints for a single Enterprise CA.
/// Returns default (empty) if `dns_host` is empty or unreachable.
/// DCOnly guard is handled by the caller (`run_modules`).
pub fn probe_enterpriseca_esc8(dns_host: &str) -> Esc8Data {
    if dns_host.is_empty() {
        return Esc8Data::default();
    }
    match check_esc8(dns_host) {
        Some(result) => Esc8Data::from(result),
        None         => Esc8Data::default(),
    }
}