//! Group Policy Object (GPO) processing and parsing modules.
//!
//! Provides utilities for parsing Group Policy templates, such as
//! `GptTmpl.inf` security privilege assignments.

pub mod gpttmpl;
pub mod types;

pub use gpttmpl::{decode_gpttmpl_bytes, parse_gpttmpl, parse_gpttmpl_bytes};
pub use types::{GpoError, GptTmplPolicy, PrivilegeAssignment};
