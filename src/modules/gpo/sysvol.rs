//! SYSVOL collection for Group Policy.
//!
//! Connects to the DC SYSVOL share, walks the Policies directory and reads the
//! per GPO template files, then feeds the existing parsers:
//!   * GptTmpl.inf  -> Privilege Rights (#47) and Restricted Groups (#56)
//!   * Groups.xml   -> GPP local group membership (#56)
//!
//! This layer only retrieves and parses directives. Mapping them to graph edges
//! (GPO GUID -> links -> affected computers, name -> SID) belongs to a later
//! layer, matching the module's existing split.

use std::collections::HashSet;

use log::{debug, info, warn};

use crate::objects::gpo::Gpo;
use crate::transport::smb::{connect_sysvol, list_dir, try_read_file, SmbAuth};

use super::types::{GppLocalGroup, PrivilegeAssignment, RestrictedGroupDirective};
use super::{parse_gpttmpl_bytes, parse_groups_xml};

/// Directives collected from one GPO's SYSVOL files.
#[derive(Debug, Default)]
pub struct SysvolGpo {
    pub guid: String,
    pub privileges: Vec<PrivilegeAssignment>,
    pub restricted_groups: Vec<RestrictedGroupDirective>,
    pub gpp_local_groups: Vec<GppLocalGroup>,
}

impl SysvolGpo {
    fn new(guid: String) -> Self {
        SysvolGpo {
            guid,
            ..Default::default()
        }
    }
    fn has_directives(&self) -> bool {
        !self.privileges.is_empty()
            || !self.restricted_groups.is_empty()
            || !self.gpp_local_groups.is_empty()
    }
}

/// Canonical SYSVOL file paths for one GPO, relative to the share root.
struct GpoFiles {
    gpttmpl: String,
    groups_machine: String,
    groups_user: String,
}

fn gpo_file_paths(policies_root: &str, guid: &str) -> GpoFiles {
    let base = format!(r"{policies_root}\{guid}");
    GpoFiles {
        gpttmpl: format!(r"{base}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"),
        groups_machine: format!(r"{base}\Machine\Preferences\Groups\Groups.xml"),
        groups_user: format!(r"{base}\User\Preferences\Groups\Groups.xml"),
    }
}

/// A Policies entry is a GPO when it is a "{GUID}" folder.
fn is_gpo_guid(name: &str) -> bool {
    name.len() >= 3 && name.starts_with('{') && name.ends_with('}')
}

/// Connect to `dc_host` SYSVOL and collect GPO directives.
///
/// `domain_fqdn` is the SYSVOL sub-root (e.g. "DOMAIN.LOCAL"), `domain`/`user`
/// and `auth` are the SMB credentials.
pub async fn collect(
    dc_host: &str,
    domain_fqdn: &str,
    domain: &str,
    user: &str,
    auth: SmbAuth<'_>,
    scope: &ComputerGpoScope,
) -> anyhow::Result<Vec<SysvolGpo>> {
    let mut smb = connect_sysvol(dc_host, domain, user, auth).await?;

    let policies_root = format!(r"{domain_fqdn}\Policies");
    let entries = list_dir(&mut smb, dc_host, &policies_root).await?;

    let mut out = Vec::new();
    for entry in entries {
        if !entry.is_dir || !is_gpo_guid(&entry.name) {
            continue;
        }
        if !scope.allows(&entry.name) {
            debug!(
                "[gpo] skipping computer-disabled GPO {} before SYSVOL reads",
                entry.name
            );
            continue;
        }
        let files = gpo_file_paths(&policies_root, &entry.name);
        let mut gpo = SysvolGpo::new(entry.name);

        // GptTmpl.inf: Privilege Rights (#47) and Restricted Groups (#56).
        match try_read_file(&mut smb, dc_host, &files.gpttmpl).await {
            Ok(Some(bytes)) => match parse_gpttmpl_bytes(&bytes) {
                Ok(policy) => {
                    gpo.privileges = policy.privilege_rights().to_vec();
                    gpo.restricted_groups = policy.restricted_groups().to_vec();
                }
                Err(err) => warn!("[gpo] {} GptTmpl.inf parse: {err}", gpo.guid),
            },
            Ok(None) => {} // absent, normal
            Err(_) => {}   // real error already logged by try_read_file
        }

        // GPP Groups.xml: local group membership (#56), machine and user scope.
        for path in [&files.groups_machine, &files.groups_user] {
            match try_read_file(&mut smb, dc_host, path).await {
                Ok(Some(bytes)) => match parse_groups_xml(&bytes) {
                    Ok(mut groups) => gpo.gpp_local_groups.append(&mut groups),
                    Err(err) => warn!("[gpo] {} Groups.xml parse: {err}", gpo.guid),
                },
                Ok(None) => {}
                Err(_) => {}
            }
        }

        if gpo.has_directives() {
            debug!(
                "[gpo] {} -> {} privilege(s), {} restricted group(s), {} GPP group(s)",
                gpo.guid,
                gpo.privileges.len(),
                gpo.restricted_groups.len(),
                gpo.gpp_local_groups.len()
            );
            out.push(gpo);
        }
    }

    info!(
        "[gpo] collected directives from {} GPO(s) on {dc_host} SYSVOL",
        out.len()
    );
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use ldap3::SearchEntry;

    use crate::modules::gpo::local_group::{
        compute_merged, resolve_privileges, Resolver, TypedPrincipal,
    };
    use crate::modules::gpo::{parse_gpttmpl, parse_groups_xml};
    use crate::objects::gpo::Gpo;

    struct FakeResolver;

    impl Resolver for FakeResolver {
        fn resolve_name(&self, _name: &str) -> Option<(String, String)> {
            None
        }

        fn type_of_sid(&self, _sid: &str) -> Option<String> {
            Some("User".to_string())
        }
    }

    fn parsed_gpo(guid: &str, flags: &str) -> Gpo {
        let result = SearchEntry {
            dn: format!("CN={guid},CN=Policies,CN=System,DC=example,DC=local"),
            attrs: HashMap::from([
                ("displayName".to_string(), vec![format!("GPO {flags}")]),
                (
                    "gPCFileSysPath".to_string(),
                    vec![format!(
                        r"\\example.local\SYSVOL\example.local\Policies\{guid}"
                    )],
                ),
                ("flags".to_string(), vec![flags.to_string()]),
            ]),
            bin_attrs: HashMap::new(),
        };
        let mut gpo = Gpo::new();
        gpo.parse(
            result,
            "example.local",
            &mut HashMap::new(),
            &mut HashMap::new(),
            "S-1-5-21-111111111-222222222-333333333",
            &HashMap::new(),
        )
        .unwrap();
        gpo
    }

    fn sysvol_policy(guid: &str, principal_rid: u32) -> SysvolGpo {
        let principal = format!("S-1-5-21-111111111-222222222-333333333-{principal_rid}");
        let inf = format!(
            "[Privilege Rights]\nSeRemoteInteractiveLogonRight = *{principal}\n\
             [Group Membership]\n*S-1-5-32-544__Members = *{principal}\n"
        );
        let parsed_inf = parse_gpttmpl(&inf).unwrap();
        let xml = format!(
            r#"<Groups>
<Group><Properties action="U" groupSid="S-1-5-32-555"><Members><Member sid="{principal}" action="ADD"/></Members></Properties></Group>
<Group><Properties action="U" groupSid="S-1-5-32-562"><Members><Member sid="{principal}" action="ADD"/></Members></Properties></Group>
<Group><Properties action="U" groupSid="S-1-5-32-580"><Members><Member sid="{principal}" action="ADD"/></Members></Properties></Group>
</Groups>"#
        );

        SysvolGpo {
            guid: guid.to_string(),
            privileges: parsed_inf.privilege_rights().to_vec(),
            restricted_groups: parsed_inf.restricted_groups().to_vec(),
            gpp_local_groups: parse_groups_xml(xml.as_bytes()).unwrap(),
        }
    }

    fn assert_no_sid_suffix(principals: &[TypedPrincipal], suffix: &str) {
        assert!(
            principals
                .iter()
                .all(|principal| !principal.sid.ends_with(suffix)),
            "found computer-disabled principal ending in {suffix}: {principals:?}",
        );
    }

    #[test]
    fn gpo_file_paths_are_canonical() {
        let f = gpo_file_paths(
            r"DOMAIN.LOCAL\Policies",
            "{31B2F340-016D-11D2-945F-00C04FB984F9}",
        );
        assert_eq!(
            f.gpttmpl,
            r"DOMAIN.LOCAL\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
        );
        assert_eq!(
            f.groups_machine,
            r"DOMAIN.LOCAL\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml"
        );
        assert!(f
            .groups_user
            .ends_with(r"\User\Preferences\Groups\Groups.xml"));
    }

    #[test]
    fn is_gpo_guid_accepts_guid_folders_only() {
        assert!(is_gpo_guid("{31B2F340-016D-11D2-945F-00C04FB984F9}"));
        assert!(!is_gpo_guid("PolicyDefinitions"));
        assert!(!is_gpo_guid("."));
        assert!(!is_gpo_guid(".."));
        assert!(!is_gpo_guid(""));
        assert!(!is_gpo_guid("{"));
    }

    #[test]
    fn has_directives_reflects_content() {
        let mut g = SysvolGpo::new("{G}".into());
        assert!(!g.has_directives());
        g.privileges.push(PrivilegeAssignment::new(
            "SeDebugPrivilege",
            vec!["DOMAIN\\alice".into()],
        ));
        assert!(g.has_directives());
    }

    #[test]
    fn computer_scope_allows_flags_zero_and_one_only() {
        let guids = [
            "{AbCdEfAb-CdEf-AbCd-EfAb-CdEfAbCdEfAb}",
            "{11111111-1111-1111-1111-111111111111}",
            "{22222222-2222-2222-2222-222222222222}",
            "{33333333-3333-3333-3333-333333333333}",
        ];
        let gpos: Vec<Gpo> = guids
            .iter()
            .zip(["0", "1", "2", "3"])
            .map(|(guid, flags)| parsed_gpo(guid, flags))
            .collect();

        let scope = ComputerGpoScope::from_gpos(&gpos);

        assert!(scope.allows(guids[0]));
        assert!(scope.allows(&guids[0].to_ascii_uppercase()));
        assert!(scope.allows(&guids[0].to_ascii_lowercase()));
        assert!(scope.allows(guids[1]));
        assert!(!scope.allows(guids[2]));
        assert!(!scope.allows(guids[3]));
    }

    #[test]
    fn flags_two_and_three_leave_no_local_group_or_user_right_output() {
        let guids = [
            "{00000000-0000-0000-0000-000000000000}",
            "{11111111-1111-1111-1111-111111111111}",
            "{22222222-2222-2222-2222-222222222222}",
            "{33333333-3333-3333-3333-333333333333}",
        ];
        let metadata: Vec<Gpo> = guids
            .iter()
            .zip(["0", "1", "2", "3"])
            .map(|(guid, flags)| parsed_gpo(guid, flags))
            .collect();
        let sysvol: Vec<SysvolGpo> = guids
            .iter()
            .enumerate()
            .map(|(flags, guid)| sysvol_policy(guid, 1000 + flags as u32))
            .collect();
        let scope = ComputerGpoScope::from_gpos(&metadata);
        let applicable = scope.applicable(&sysvol);

        assert_eq!(
            applicable
                .iter()
                .map(|gpo| gpo.guid.as_str())
                .collect::<Vec<_>>(),
            vec![guids[0], guids[1]],
        );

        let merged = compute_merged(&applicable, &FakeResolver);
        for principals in [
            &merged.local_admins,
            &merged.remote_desktop_users,
            &merged.dcom_users,
            &merged.psremote_users,
        ] {
            assert_no_sid_suffix(principals, "1002");
            assert_no_sid_suffix(principals, "1003");
        }

        let privileges = resolve_privileges(&applicable, &FakeResolver);
        assert_eq!(privileges.len(), 1);
        assert_no_sid_suffix(&privileges[0].1, "1002");
        assert_no_sid_suffix(&privileges[0].1, "1003");
    }
}

/// GPO folders whose computer configuration is applicable according to LDAP.
#[derive(Debug, Default)]
pub struct ComputerGpoScope {
    guids: HashSet<String>,
}

impl ComputerGpoScope {
    pub fn from_gpos(gpos: &[Gpo]) -> Self {
        let guids = gpos
            .iter()
            .filter(|gpo| gpo.computer_configuration_enabled())
            .filter_map(Gpo::sysvol_guid)
            .collect();
        Self { guids }
    }

    pub(crate) fn allows(&self, guid: &str) -> bool {
        self.guids.contains(&guid.to_uppercase())
    }

    #[cfg(test)]
    pub(crate) fn applicable<'a>(&self, gpos: &'a [SysvolGpo]) -> Vec<&'a SysvolGpo> {
        gpos.iter().filter(|gpo| self.allows(&gpo.guid)).collect()
    }
}
