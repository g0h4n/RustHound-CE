//! Group Policy Object (GPO) processing and parsing modules.
//!
//! Provides utilities for parsing Group Policy templates, such as
//! `GptTmpl.inf` privilege and Restricted Groups assignments and GPP `Groups.xml`.
//! These parsers preserve directives; retrieval, applicability and graph edges
//! belong to future layers.

pub mod gpttmpl;
pub mod groups_xml;
pub mod types;
pub mod sysvol;

pub use gpttmpl::{decode_gpttmpl_bytes, parse_gpttmpl, parse_gpttmpl_bytes};
pub use groups_xml::parse_groups_xml;
pub use types::{
    GpoError, GppGroupAction, GppGroupMember, GppLocalGroup, GppMemberAction, GptTmplPolicy,
    PrivilegeAssignment, RestrictedGroupDirective, RestrictedGroupOperation,
};
pub use sysvol::{collect as collect_sysvol, SysvolGpo};