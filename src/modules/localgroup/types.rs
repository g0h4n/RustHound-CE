//! Internal types for the local-group module.

/// One BUILTIN alias to read: its RID, display name, and BloodHound edge.
#[derive(Clone, Copy, Debug)]
pub struct Alias {
    pub rid: u32,
    pub name: &'static str,
    pub edge: &'static str,
}

/// The four aliases SharpHound reads, in its own order.
/// ref: SharpHoundCommon v4.8.0 LocalGroupRids
pub const ALIASES: &[Alias] = &[
    Alias { rid: 544, name: "Administrators", edge: "AdminTo" },
    Alias { rid: 555, name: "Remote Desktop Users", edge: "CanRDP" },
    Alias { rid: 562, name: "Distributed COM Users", edge: "ExecuteDCOM" },
    Alias { rid: 580, name: "Remote Management Users", edge: "CanPSRemote" },
];

/// One alias read on one host.
pub struct AliasFinding {
    /// The BloodHound ObjectIdentifier of the group.
    pub group_sid: String,
    /// The alias display name, used to build the LocalGroup `Name` field.
    pub group_name: &'static str,
    pub members: Vec<String>,
    pub collected: bool,
    pub failure: Option<String>,
}

/// Everything learned about one host, folded into its Computer afterwards.
pub struct HostFindings {
    pub computer_sid: String,
    /// FQDN, used to build "<GROUP>@<HOST>" names on a member host.
    pub host: String,
    /// True on a DC, where BloodHound must not get a duplicate group node.
    pub is_dc: bool,
    pub aliases: Vec<AliasFinding>,
    pub errors: Vec<String>,
}

/// The group's `Name` field, which tells BloodHound whether to (re)create the
/// LocalGroup node. On a DC the BUILTIN alias is the domain group already in the
/// graph, so the sentinel suppresses a duplicate; on a member host it is
/// "<GROUP NAME>@<HOST>", matching SharpHound.
pub const IGNORED_NAME: &str = "IGNOREME";

pub fn group_display_name(group_name: &str, host: &str, is_dc: bool) -> String {
    if is_dc {
        IGNORED_NAME.to_string()
    } else {
        format!("{}@{}", group_name, host).to_uppercase()
    }
}

/// The group's ObjectIdentifier, in SharpHound's two forms.
pub fn group_object_id(rid: u32, domain: &str, is_dc: bool, computer_sid: &str) -> String {
    if is_dc {
        format!("{}-S-1-5-32-{rid}", domain.to_uppercase())
    } else {
        format!("{computer_sid}-{rid}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_display_name_member_vs_dc() {
        // Member host: "<GROUP>@<HOST>", uppercased, matching SharpHound.
        assert_eq!(
            group_display_name("Remote Desktop Users", "BRAAVOS.ESSOS.LOCAL", false),
            "REMOTE DESKTOP USERS@BRAAVOS.ESSOS.LOCAL"
        );
        // DC: the sentinel that stops BloodHound duplicating the domain group.
        assert_eq!(
            group_display_name("Remote Desktop Users", "MEEREEN.ESSOS.LOCAL", true),
            "IGNOREME"
        );
    }

}