//! GPO local group and privilege resolution.
//!
//! Turns the SYSVOL directives collected per GPO into the two BloodHound
//! outputs:
//!
//!   [Group Membership] / Groups.xml -> GPOChanges on OU and Domain objects
//!       Administrators (544)        -> LocalAdmins        -> AdminTo
//!       Remote Desktop Users (555)  -> RemoteDesktopUsers -> CanRDP
//!       Distributed COM Users (562) -> DcomUsers          -> ExecuteDCOM
//!       Remote Management Users(580)-> PSRemoteUsers      -> CanPSRemote
//!
//!   [Privilege Rights] (SeXxx)      -> UserRights on the affected Computers
//!
//! Mirrors SharpHound GPOLocalGroupProcessor for the merge semantics. It reuses
//! the checker's work: AffectedComputers is already set (add_affected_computers*)
//! and links already carry the GPO SID (replace_guid_gplink), so this layer only
//! fills the four local-group vecs and the computers' UserRights.

use std::collections::HashMap;

use crate::objects::common::{GPOChange, LdapObject, Link, Member, UserRight};
use crate::objects::computer::Computer;
use crate::objects::domain::Domain;
use crate::objects::group::Group;
use crate::objects::ou::Ou;
use crate::objects::user::User;

use super::sysvol::SysvolGpo;
use super::types::{
    GppGroupAction, GppMemberAction, RestrictedGroupDirective,
    RestrictedGroupOperation,
};

// ---- group identity ----------------------------------------------------------

/// One of the four built-in local groups tracked for lateral movement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetGroup {
    LocalAdmins,
    RemoteDesktopUsers,
    DcomUsers,
    PsRemote,
}

impl TargetGroup {
    fn from_rid(rid: u32) -> Option<Self> {
        match rid {
            544 => Some(Self::LocalAdmins),
            555 => Some(Self::RemoteDesktopUsers),
            562 => Some(Self::DcomUsers),
            580 => Some(Self::PsRemote),
            _ => None,
        }
    }

    fn from_group_name(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "administrators" => Some(Self::LocalAdmins),
            "remote desktop users" => Some(Self::RemoteDesktopUsers),
            "distributed com users" => Some(Self::DcomUsers),
            "remote management users" => Some(Self::PsRemote),
            _ => None,
        }
    }
}

/// A resolved principal: SID plus BloodHound object type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedPrincipal {
    pub sid: String,
    pub object_type: String,
}

// ---- resolution --------------------------------------------------------------

/// Name/SID -> (SID, type) resolution, backed by the collected LDAP objects.
pub trait Resolver {
    fn resolve_name(&self, name: &str) -> Option<(String, String)>;
    fn type_of_sid(&self, sid: &str) -> Option<String>;
}

/// Resolver built from the users / groups / computers collected over LDAP.
pub struct ObjectResolver {
    by_name: HashMap<String, (String, String)>, // UPPER bare SAM -> (sid, type)
    by_sid: HashMap<String, String>,            // UPPER sid -> type
}

fn index_object(
    sid: &str,
    display: &str,
    ty: &str,
    by_name: &mut HashMap<String, (String, String)>,
    by_sid: &mut HashMap<String, String>,
) {
    if sid.is_empty() {
        return;
    }
    by_sid.insert(sid.to_uppercase(), ty.to_string());
    let bare = display
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(display)
        .split('@')
        .next()
        .unwrap_or(display)
        .trim()
        .to_uppercase();
    if !bare.is_empty() {
        by_name
            .entry(bare)
            .or_insert_with(|| (sid.to_string(), ty.to_string()));
    }
}

impl ObjectResolver {
    pub fn build(users: &[User], groups: &[Group], computers: &[Computer]) -> Self {
        let mut by_name = HashMap::new();
        let mut by_sid = HashMap::new();

        for u in users {
            index_object(u.object_identifier(), u.properties().name(), "User", &mut by_name, &mut by_sid);
        }
        for g in groups {
            index_object(g.object_identifier(), g.properties().name(), "Group", &mut by_name, &mut by_sid);
        }
        for c in computers {
            let sid = c.object_identifier();
            let name = c.properties().name();
            index_object(sid, name, "Computer", &mut by_name, &mut by_sid);
            let short = name.split('.').next().unwrap_or(name).to_uppercase();
            if !short.is_empty() {
                by_name
                    .entry(format!("{short}$"))
                    .or_insert_with(|| (sid.to_string(), "Computer".to_string()));
            }
        }

        ObjectResolver { by_name, by_sid }
    }
}

impl Resolver for ObjectResolver {
    fn resolve_name(&self, name: &str) -> Option<(String, String)> {
        self.by_name.get(&name.to_uppercase()).cloned()
    }
    fn type_of_sid(&self, sid: &str) -> Option<String> {
        self.by_sid.get(&sid.to_uppercase()).cloned()
    }
}

/// Extract the RID from an "S-1-5-32-XXX" built-in SID (any leading '*' ok).
fn builtin_rid(s: &str) -> Option<u32> {
    let up = s.trim().trim_start_matches('*').to_uppercase();
    let rest = up.strip_prefix("S-1-5-32-")?;
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// Resolve a raw principal string (SID or name) to a typed principal.
fn resolve_principal(raw: &str, resolver: &impl Resolver) -> Option<TypedPrincipal> {
    let p = raw.trim().trim_start_matches('*').trim();
    if p.is_empty() {
        return None;
    }
    if p.len() >= 4 && p[..4].eq_ignore_ascii_case("S-1-") {
        let sid = p.to_uppercase();
        let object_type = resolver.type_of_sid(&sid).unwrap_or_else(|| "Base".to_string());
        return Some(TypedPrincipal { sid, object_type });
    }
    let bare = p.rsplit(['\\', '/']).next().unwrap_or(p);
    resolver
        .resolve_name(bare)
        .map(|(sid, object_type)| TypedPrincipal { sid, object_type })
}

// ---- action model (internal), mirrors SharpHound GroupAction -----------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Add,
    Delete,
    DeleteUsers,
    DeleteGroups,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    RestrictedMember,
    RestrictedMemberOf,
    LocalGroup,
}

#[derive(Debug, Clone)]
struct Action {
    group: TargetGroup,
    kind: Kind,
    op: Op,
    principal: Option<TypedPrincipal>,
}

/// Build the ordered action list for a single GPO (GPP first, then GptTmpl).
fn actions_for_gpo(gpo: &SysvolGpo, resolver: &impl Resolver) -> Vec<Action> {
    let mut out = Vec::new();

    for grp in &gpo.gpp_local_groups {
        if grp.action() != GppGroupAction::Update {
            continue;
        }
        let target = grp
            .sid()
            .and_then(builtin_rid)
            .and_then(TargetGroup::from_rid)
            .or_else(|| grp.name().and_then(TargetGroup::from_group_name));
        let Some(group) = target else { continue };

        if grp.delete_all_users() {
            out.push(Action { group, kind: Kind::LocalGroup, op: Op::DeleteUsers, principal: None });
        }
        if grp.delete_all_groups() {
            out.push(Action { group, kind: Kind::LocalGroup, op: Op::DeleteGroups, principal: None });
        }
        for m in grp.members() {
            let op = match m.action() {
                GppMemberAction::Add => Op::Add,
                GppMemberAction::Remove => Op::Delete,
            };
            let principal = m
                .sid()
                .and_then(|s| resolve_principal(s, resolver))
                .or_else(|| m.name().and_then(|n| resolve_principal(n, resolver)));
            if let Some(p) = principal {
                out.push(Action { group, kind: Kind::LocalGroup, op, principal: Some(p) });
            }
        }
    }

    for dir in &gpo.restricted_groups {
        push_restricted(dir, resolver, &mut out);
    }

    out
}

fn push_restricted(dir: &RestrictedGroupDirective, resolver: &impl Resolver, out: &mut Vec<Action>) {
    match dir.operation() {
        RestrictedGroupOperation::ReplaceMembers => {
            let Some(group) = builtin_rid(dir.target()).and_then(TargetGroup::from_rid) else {
                return;
            };
            for raw in dir.principals() {
                if let Some(p) = resolve_principal(raw, resolver) {
                    out.push(Action { group, kind: Kind::RestrictedMember, op: Op::Add, principal: Some(p) });
                }
            }
        }
        RestrictedGroupOperation::AddToParentGroups => {
            let Some(member) = resolve_principal(dir.target(), resolver) else {
                return;
            };
            for raw in dir.principals() {
                if let Some(group) = builtin_rid(raw).and_then(TargetGroup::from_rid) {
                    out.push(Action {
                        group,
                        kind: Kind::RestrictedMemberOf,
                        op: Op::Add,
                        principal: Some(member.clone()),
                    });
                }
            }
        }
    }
}

// ---- merge -------------------------------------------------------------------

/// The four resulting member sets after merging all linked GPOs.
#[derive(Debug, Default)]
pub struct MergedGroups {
    pub local_admins: Vec<TypedPrincipal>,
    pub remote_desktop_users: Vec<TypedPrincipal>,
    pub dcom_users: Vec<TypedPrincipal>,
    pub psremote_users: Vec<TypedPrincipal>,
}

fn dedup_by_sid(v: &mut Vec<TypedPrincipal>) {
    let mut seen = std::collections::HashSet::new();
    v.retain(|p| seen.insert(p.sid.clone()));
}

/// final = RestrictedMemberOf + (RestrictedMember if any, else LocalGroups), distinct.
fn merge(actions: &[Action]) -> MergedGroups {
    let mut merged = MergedGroups::default();
    for group in [
        TargetGroup::LocalAdmins,
        TargetGroup::RemoteDesktopUsers,
        TargetGroup::DcomUsers,
        TargetGroup::PsRemote,
    ] {
        let mut restricted_member: Vec<TypedPrincipal> = Vec::new();
        let mut restricted_memberof: Vec<TypedPrincipal> = Vec::new();
        let mut local_groups: Vec<TypedPrincipal> = Vec::new();

        for a in actions.iter().filter(|a| a.group == group) {
            match (a.kind, a.op) {
                (Kind::RestrictedMember, _) => {
                    if let Some(p) = &a.principal { restricted_member.push(p.clone()); }
                }
                (Kind::RestrictedMemberOf, _) => {
                    if let Some(p) = &a.principal { restricted_memberof.push(p.clone()); }
                }
                (Kind::LocalGroup, Op::Add) => {
                    if let Some(p) = &a.principal { local_groups.push(p.clone()); }
                }
                (Kind::LocalGroup, Op::Delete) => {
                    if let Some(p) = &a.principal { local_groups.retain(|x| x.sid != p.sid); }
                }
                (Kind::LocalGroup, Op::DeleteUsers) => {
                    local_groups.retain(|x| x.object_type != "User");
                }
                (Kind::LocalGroup, Op::DeleteGroups) => {
                    local_groups.retain(|x| x.object_type != "Group");
                }
            }
        }

        let mut final_set = restricted_memberof;
        if restricted_member.is_empty() {
            final_set.extend(local_groups);
        } else {
            final_set.extend(restricted_member);
        }
        dedup_by_sid(&mut final_set);

        match group {
            TargetGroup::LocalAdmins => merged.local_admins = final_set,
            TargetGroup::RemoteDesktopUsers => merged.remote_desktop_users = final_set,
            TargetGroup::DcomUsers => merged.dcom_users = final_set,
            TargetGroup::PsRemote => merged.psremote_users = final_set,
        }
    }
    merged
}

/// Compute the merged local groups for a container from its linked GPOs
/// (already ordered: unenforced first, then enforced).
pub fn compute_merged(ordered_gpos: &[&SysvolGpo], resolver: &impl Resolver) -> MergedGroups {
    let mut actions = Vec::new();
    for gpo in ordered_gpos {
        actions.extend(actions_for_gpo(gpo, resolver));
    }
    merge(&actions)
}

/// Merge privilege assignments across linked GPOs (union per privilege, dedup by SID).
pub fn resolve_privileges(
    ordered_gpos: &[&SysvolGpo],
    resolver: &impl Resolver,
) -> Vec<(String, Vec<TypedPrincipal>)> {
    let mut order: Vec<String> = Vec::new();
    let mut map: HashMap<String, Vec<TypedPrincipal>> = HashMap::new();

    for gpo in ordered_gpos {
        for pa in &gpo.privileges {
            let key = pa.privilege().to_string();
            if !map.contains_key(&key) {
                order.push(key.clone());
                map.insert(key.clone(), Vec::new());
            }
            let entry = map.get_mut(&key).unwrap();
            for raw in pa.principals() {
                if let Some(p) = resolve_principal(raw, resolver) {
                    if !entry.iter().any(|x| x.sid == p.sid) {
                        entry.push(p);
                    }
                }
            }
        }
    }
    order.into_iter().map(|k| { let v = map.remove(&k).unwrap(); (k, v) }).collect()
}

// ---- output helpers ----------------------------------------------------------

fn to_member(p: &TypedPrincipal) -> Member {
    let mut m = Member::new();
    *m.object_identifier_mut() = p.sid.clone();
    *m.object_type_mut() = p.object_type.clone();
    m
}

fn to_members(list: &[TypedPrincipal]) -> Vec<Member> {
    list.iter().map(to_member).collect()
}

// ---- driver (reuses the checker: no affected-computers recompute, no GUID
//      extraction; links already carry the GPO SID) -----------------------------

/// Fill GPOChanges (local groups) on OU/Domain and UserRights (privileges) on
/// the affected computers already resolved by the checker.
///
/// `dn_sid` (ad.mappings.dn_sid) bridges each GPO SYSVOL folder GUID to its SID,
/// so links (whose GUID was replaced with the GPO SID by replace_guid_gplink)
/// can be matched back to the collected directives.
pub fn apply_gpo(
    ous: &mut [Ou],
    domains: &mut [Domain],
    users: &[User],
    groups: &[Group],
    computers: &mut Vec<Computer>,
    sysvol: &[SysvolGpo],
    dn_sid: &HashMap<String, String>,
) {
    let resolver = ObjectResolver::build(users, groups, computers);

    // folder GUID -> GPO SID, the same way replace_guid_gplink matched links.
    let mut by_sid: HashMap<String, &SysvolGpo> = HashMap::new();
    for g in sysvol {
        let needle = g.guid.to_uppercase();
        if let Some((_, sid)) = dn_sid.iter().find(|(dn, _)| dn.to_uppercase().contains(&needle)) {
            by_sid.insert(sid.to_uppercase(), g);
        }
    }

    // computer SID -> (privilege -> members), accumulated across containers.
    let mut priv_acc: HashMap<String, HashMap<String, Vec<TypedPrincipal>>> = HashMap::new();

    for ou in ous.iter_mut() {
        let links: Vec<Link> = ou.get_links().to_vec();
        fill_container(&links, ou.gpo_changes_mut(), &by_sid, &resolver, &mut priv_acc);
    }
    for dom in domains.iter_mut() {
        let links: Vec<Link> = dom.get_links().to_vec();
        fill_container(&links, dom.gpo_changes_mut(), &by_sid, &resolver, &mut priv_acc);
    }

    for c in computers.iter_mut() {
        let Some(per) = priv_acc.get(c.object_identifier()) else { continue };
        let ur = c.users_rights_mut();
        for (privilege, members) in per {
            let mut right = UserRight::new();
            *right.privilege_mut() = privilege.clone();
            *right.results_mut() = to_members(members);
            *right.collected_mut() = true;
            ur.push(right);
        }
    }
}

fn fill_container(
    links_src: &[Link],
    changes: &mut GPOChange,
    by_sid: &HashMap<String, &SysvolGpo>,
    resolver: &impl Resolver,
    priv_acc: &mut HashMap<String, HashMap<String, Vec<TypedPrincipal>>>,
) {
    // Links now hold (is_enforced, GPO SID). Order unenforced first, then enforced.
    let mut links: Vec<(bool, String)> = links_src
        .iter()
        .map(|l| (*l.is_enforced(), l.guid().clone()))
        .collect();
    if links.is_empty() {
        return;
    }
    links.sort_by_key(|(enforced, _)| *enforced);

    let ordered: Vec<&SysvolGpo> = links
        .iter()
        .filter_map(|(_, sid)| by_sid.get(&sid.to_uppercase()).copied())
        .collect();
    if ordered.is_empty() {
        return;
    }

    // Local groups -> this container's GPOChanges (AffectedComputers preserved).
    let merged = compute_merged(&ordered, resolver);
    *changes.local_admins_mut() = to_members(&merged.local_admins);
    *changes.remote_desktop_users_mut() = to_members(&merged.remote_desktop_users);
    *changes.dcom_users_mut() = to_members(&merged.dcom_users);
    *changes.psremote_users_mut() = to_members(&merged.psremote_users);

    // Privileges -> accumulate onto the computers the checker already resolved.
    let privs = resolve_privileges(&ordered, resolver);
    if privs.is_empty() {
        return;
    }
    for m in changes.affected_computers() {
        let per = priv_acc.entry(m.object_identifier().clone()).or_default();
        for (privilege, members) in &privs {
            let e = per.entry(privilege.clone()).or_default();
            for p in members {
                if !e.iter().any(|x| x.sid == p.sid) {
                    e.push(p.clone());
                }
            }
        }
    }
}

// ---- tests -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeResolver;
    impl Resolver for FakeResolver {
        fn resolve_name(&self, name: &str) -> Option<(String, String)> {
            match name.to_uppercase().as_str() {
                "ALICE" => Some(("S-1-5-21-1-1-1105".into(), "User".into())),
                "HELPDESK" => Some(("S-1-5-21-1-1-1200".into(), "Group".into())),
                _ => None,
            }
        }
        fn type_of_sid(&self, sid: &str) -> Option<String> {
            match sid {
                "S-1-5-21-1-1-512" => Some("Group".into()),
                _ => None,
            }
        }
    }

    fn gpo_with_restricted(target: &str, op: RestrictedGroupOperation, principals: &[&str]) -> SysvolGpo {
        let mut g = SysvolGpo::default();
        g.guid = "{G}".into();
        g.restricted_groups = vec![RestrictedGroupDirective::new(
            target,
            op,
            principals.iter().map(|s| s.to_string()).collect(),
        )];
        g
    }

    #[test]
    fn replace_members_fills_local_admins() {
        let g = gpo_with_restricted(
            "S-1-5-32-544",
            RestrictedGroupOperation::ReplaceMembers,
            &["*S-1-5-21-1-1-512", "*ALICE"],
        );
        let merged = compute_merged(&[&g], &FakeResolver);
        let sids: Vec<&str> = merged.local_admins.iter().map(|p| p.sid.as_str()).collect();
        assert_eq!(sids, vec!["S-1-5-21-1-1-512", "S-1-5-21-1-1-1105"]);
        assert_eq!(merged.local_admins[0].object_type, "Group");
        assert_eq!(merged.local_admins[1].object_type, "User");
        assert!(merged.remote_desktop_users.is_empty());
    }

    #[test]
    fn memberof_targets_the_parent_group_rid() {
        let g = gpo_with_restricted(
            "HELPDESK",
            RestrictedGroupOperation::AddToParentGroups,
            &["S-1-5-32-555"],
        );
        let merged = compute_merged(&[&g], &FakeResolver);
        assert_eq!(merged.remote_desktop_users.len(), 1);
        assert_eq!(merged.remote_desktop_users[0].sid, "S-1-5-21-1-1-1200");
        assert!(merged.local_admins.is_empty());
    }

    #[test]
    fn restricted_member_overrides_local_groups() {
        let g = gpo_with_restricted(
            "S-1-5-32-544",
            RestrictedGroupOperation::ReplaceMembers,
            &["*ALICE"],
        );
        let merged = compute_merged(&[&g], &FakeResolver);
        assert_eq!(merged.local_admins.len(), 1);
        assert_eq!(merged.local_admins[0].sid, "S-1-5-21-1-1-1105");
    }

    // #[test]
    // fn privileges_resolve_and_union_by_sid() {
    //     let mut g = SysvolGpo::default();
    //     g.guid = "{G}".into();
    //     g.privileges = vec![PrivilegeAssignment::new(
    //         "SeRemoteInteractiveLogonRight",
    //         vec!["*S-1-5-21-1-1-512".into(), "*ALICE".into(), "*S-1-5-21-1-1-512".into()],
    //     )];
    //     let out = resolve_privileges(&[&g], &FakeResolver);
    //     assert_eq!(out.len(), 1);
    //     assert_eq!(out[0].0, "SeRemoteInteractiveLogonRight");
    //     let sids: Vec<&str> = out[0].1.iter().map(|p| p.sid.as_str()).collect();
    //     assert_eq!(sids, vec!["S-1-5-21-1-1-512", "S-1-5-21-1-1-1105"]);
    // }
}