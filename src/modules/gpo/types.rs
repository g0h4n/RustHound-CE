use std::fmt;

/// Custom error types for GPO operations and parsing.
#[derive(Debug)]
pub enum GpoError {
    /// The input bytes could not be decoded with a supported character encoding.
    InvalidEncoding(String),
    /// The content of the policy file is malformed.
    MalformedContent(String),
    /// An underlying I/O error occurred.
    Io(std::io::Error),
}

impl fmt::Display for GpoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEncoding(msg) => write!(f, "Invalid policy encoding: {msg}"),
            Self::MalformedContent(msg) => write!(f, "Malformed policy content: {msg}"),
            Self::Io(err) => write!(f, "Policy I/O error: {err}"),
        }
    }
}

impl std::error::Error for GpoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for GpoError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// Represents a single privilege right assignment from GptTmpl.inf.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PrivilegeAssignment {
    privilege: String,
    principals: Vec<String>,
}

impl PrivilegeAssignment {
    /// Creates a new `PrivilegeAssignment`.
    pub fn new(privilege: impl Into<String>, principals: Vec<String>) -> Self {
        Self {
            privilege: privilege.into(),
            principals,
        }
    }

    /// Returns the privilege name (e.g., `SeDebugPrivilege`).
    pub fn privilege(&self) -> &str {
        &self.privilege
    }

    /// Returns the raw assigned principals as stored in the policy (preserving any leading `*`).
    pub fn principals(&self) -> &[String] {
        &self.principals
    }

    /// Returns an iterator over normalized principal names/SIDs, stripping any leading `*` prefix.
    pub fn normalized_principals(&self) -> impl Iterator<Item = &str> {
        self.principals
            .iter()
            .map(|p| p.strip_prefix('*').unwrap_or(p))
    }

    /// Returns normalized principals that look like Windows SID candidates
    /// based on the `S-1-` prefix, with any leading `*` stripped.
    pub fn sid_candidates(&self) -> impl Iterator<Item = &str> {
        self.normalized_principals()
            .filter(|p| p.starts_with("S-1-") || p.starts_with("s-1-"))
    }
}

/// Represents a parsed GptTmpl.inf security policy.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GptTmplPolicy {
    privilege_rights: Vec<PrivilegeAssignment>,
    restricted_groups: Vec<RestrictedGroupDirective>,
}

impl GptTmplPolicy {
    /// Creates a new, empty `GptTmplPolicy`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new `GptTmplPolicy` with the given privilege rights.
    pub fn with_privilege_rights(privilege_rights: Vec<PrivilegeAssignment>) -> Self {
        Self {
            privilege_rights,
            restricted_groups: Vec::new(),
        }
    }

    /// Creates a policy containing both privilege assignments and Restricted Groups directives.
    pub fn with_entries(
        privilege_rights: Vec<PrivilegeAssignment>,
        restricted_groups: Vec<RestrictedGroupDirective>,
    ) -> Self {
        Self {
            privilege_rights,
            restricted_groups,
        }
    }

    /// Returns a slice of all privilege assignments.
    pub fn privilege_rights(&self) -> &[PrivilegeAssignment] {
        &self.privilege_rights
    }

    /// Looks up a privilege assignment by name (case-insensitive).
    pub fn get_privilege(&self, privilege_name: &str) -> Option<&PrivilegeAssignment> {
        self.privilege_rights
            .iter()
            .find(|p| p.privilege.eq_ignore_ascii_case(privilege_name))
    }

    /// Returns the Restricted Groups directives in source order.
    pub fn restricted_groups(&self) -> &[RestrictedGroupDirective] {
        &self.restricted_groups
    }
}

/// Describes how a Restricted Groups entry changes local group membership.
///
/// The parser preserves policy intent and deliberately does not mutate graph edges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestrictedGroupOperation {
    /// `__Members`: the listed principals are the complete membership configured by the policy.
    ReplaceMembers,
    /// `__Memberof`: the target group is added to each listed parent group.
    AddToParentGroups,
}

/// A single entry from the `[Group Membership]` section of `GptTmpl.inf`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestrictedGroupDirective {
    target: String,
    operation: RestrictedGroupOperation,
    principals: Vec<String>,
}

impl RestrictedGroupDirective {
    pub fn new(
        target: impl Into<String>,
        operation: RestrictedGroupOperation,
        principals: Vec<String>,
    ) -> Self {
        Self {
            target: target.into(),
            operation,
            principals,
        }
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn operation(&self) -> RestrictedGroupOperation {
        self.operation
    }

    pub fn principals(&self) -> &[String] {
        &self.principals
    }
}

/// Action requested by a Group Policy Preferences local-group item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GppGroupAction {
    Create,
    Delete,
    Replace,
    Update,
}

/// Action requested for a member inside a GPP local-group item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GppMemberAction {
    Add,
    Remove,
}

fn nonempty_identity(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.trim().is_empty())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GppGroupMember {
    sid: Option<String>,
    name: Option<String>,
    action: GppMemberAction,
}

impl GppGroupMember {
    pub fn new(sid: Option<String>, name: Option<String>, action: GppMemberAction) -> Self {
        Self {
            sid: nonempty_identity(sid),
            name: nonempty_identity(name),
            action,
        }
    }

    /// Returns the nonempty SID when present, otherwise the nonempty name.
    pub fn principal(&self) -> Option<&str> {
        self.sid.as_deref().or(self.name.as_deref())
    }

    pub fn sid(&self) -> Option<&str> {
        self.sid.as_deref()
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn action(&self) -> GppMemberAction {
        self.action
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GppLocalGroup {
    sid: Option<String>,
    name: Option<String>,
    action: GppGroupAction,
    delete_all_users: bool,
    delete_all_groups: bool,
    has_item_level_targeting: bool,
    members: Vec<GppGroupMember>,
}

impl GppLocalGroup {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sid: Option<String>,
        name: Option<String>,
        action: GppGroupAction,
        delete_all_users: bool,
        delete_all_groups: bool,
        has_item_level_targeting: bool,
        members: Vec<GppGroupMember>,
    ) -> Self {
        Self {
            sid: nonempty_identity(sid),
            name: nonempty_identity(name),
            action,
            delete_all_users,
            delete_all_groups,
            has_item_level_targeting,
            members,
        }
    }

    /// Returns the nonempty group SID when present, otherwise the nonempty group name.
    pub fn target(&self) -> Option<&str> {
        self.sid.as_deref().or(self.name.as_deref())
    }

    pub fn sid(&self) -> Option<&str> {
        self.sid.as_deref()
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn action(&self) -> GppGroupAction {
        self.action
    }

    pub fn delete_all_users(&self) -> bool {
        self.delete_all_users
    }

    pub fn delete_all_groups(&self) -> bool {
        self.delete_all_groups
    }

    /// If true, a future applicability layer must evaluate targeting before applying
    /// this directive; membership must never be applied globally without evaluation.
    pub fn has_item_level_targeting(&self) -> bool {
        self.has_item_level_targeting
    }

    pub fn members(&self) -> &[GppGroupMember] {
        &self.members
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privilege_assignment_normalized_principals_and_sid_candidates() {
        let assignment = PrivilegeAssignment::new(
            "SeRemoteInteractiveLogonRight",
            vec![
                "*S-1-5-32-544".to_string(),
                "S-1-5-32-545".to_string(),
                "*DOMAIN\\Administrators".to_string(),
                "LocalUser".to_string(),
            ],
        );

        assert_eq!(assignment.privilege(), "SeRemoteInteractiveLogonRight");
        assert_eq!(assignment.principals().len(), 4);

        let normalized: Vec<&str> = assignment.normalized_principals().collect();
        assert_eq!(
            normalized,
            vec![
                "S-1-5-32-544",
                "S-1-5-32-545",
                "DOMAIN\\Administrators",
                "LocalUser"
            ]
        );

        let sids: Vec<&str> = assignment.sid_candidates().collect();
        assert_eq!(sids, vec!["S-1-5-32-544", "S-1-5-32-545"]);
    }

    #[test]
    fn gpttmpl_policy_lookup_is_case_insensitive() {
        let policy = GptTmplPolicy::with_privilege_rights(vec![
            PrivilegeAssignment::new("SeDebugPrivilege", vec!["*S-1-5-32-544".to_string()]),
            PrivilegeAssignment::new(
                "SeRemoteInteractiveLogonRight",
                vec!["*S-1-5-32-555".to_string()],
            ),
        ]);

        assert!(policy.get_privilege("sedebugprivilege").is_some());
        assert!(policy.get_privilege("SEDEBUGPRIVILEGE").is_some());
        assert!(policy.get_privilege("SeDebugPrivilege").is_some());
        assert!(policy.get_privilege("SeNonExistentPrivilege").is_none());
    }

    #[test]
    fn gpo_error_display_formatting() {
        let err = GpoError::MalformedContent("invalid syntax at line 5".to_string());
        assert_eq!(
            err.to_string(),
            "Malformed policy content: invalid syntax at line 5"
        );

        let err2 = GpoError::InvalidEncoding("unsupported encoding".to_string());
        assert_eq!(
            err2.to_string(),
            "Invalid policy encoding: unsupported encoding"
        );
    }
}
