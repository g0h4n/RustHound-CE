use std::collections::HashMap;
use std::error::Error;

use aho_corasick::AhoCorasick;
use once_cell::sync::Lazy;
use rayon::prelude::*;
use regex::Regex;
use crate::enums::ldaptype::*;
use crate::objects::common::Link;
use crate::objects::{
    user::User,
    computer::Computer,
    group::Group,
    ou::Ou,
    domain::Domain,
    trust::Trust,
    inssuancepolicie::IssuancePolicie,
    common::{Member, GPOChange, LdapObject}
};
//use log::{info,debug,trace};
use crate::transport::ldap::prepare_ldap_dc;
use crate::utils::format::domain_to_dc;
use crate::enums::regex::{COMMON_RE1,DOMAIN_SID_RE1};
use indicatif::ProgressBar;
use log::{error,trace};

/// Function to add default groups
/// <https://github.com/fox-it/BloodHound.py/blob/645082e3462c93f31b571db945cde1fd7b837fb9/bloodhound/enumeration/memberships.py#L411>
pub fn add_default_groups(
    vec_groups: &mut Vec<Group>,
    vec_computers: &[Computer],
    domain: String
) -> Result<(), Box<dyn Error>> {
    let mut member_sid = "".to_owned();
    let mut domain_sid = "".to_owned();

    let mut template_member = Member::new();
    *template_member.object_type_mut() = "Computer".to_string();

    // ENTERPRISE DOMAIN CONTROLLERS
    let mut edc_group = Group::new();
    let mut sid = domain.to_uppercase();
    sid.push_str("-S-1-5-9");

    let mut name = "ENTERPRISE DOMAIN CONTROLLERS@".to_owned();
    name.push_str(&domain.to_uppercase());

    let mut vec_members: Vec<Member> = Vec::new();
    for computer in vec_computers {
        if computer.properties().get_is_dc().to_owned()
        {
            // *template_member.object_identifier_mut() = computer.object_identifier().to_string();
            // vec_members.push(template_member.to_owned());
            // let re = Regex::new(r"^S-[0-9]{1}-[0-9]{1}-[0-9]{1,}-[0-9]{1,}-[0-9]{1,}-[0-9]{1,}")?;
            // let mut sids: Vec<String> = Vec::new();
            // for sid in re.captures_iter(&computer.object_identifier().to_string())
            // {
            //     sids.push(sid[0].to_owned().to_string());
            // }
            // domain_sid = sids[0].to_string();
            *template_member.object_identifier_mut() = computer.object_identifier().clone();
            vec_members.push(template_member.clone());
            if let Some(capture) = COMMON_RE1.captures(computer.object_identifier()) {

                member_sid = capture.get(0).map(|m| m.as_str().to_string()).unwrap_or_default();

                if let Some(capture) = DOMAIN_SID_RE1.captures(computer.object_identifier()) {
                    domain_sid = capture.get(0).unwrap().as_str().to_string();
                }

            }
        }
    }

    *edc_group.object_identifier_mut() = sid;
    *edc_group.properties_mut().name_mut() = name;
    *edc_group.members_mut() = vec_members;
    *edc_group.properties_mut().domain_mut() = domain.to_owned();
    *edc_group.properties_mut().domainsid_mut() = domain_sid.to_owned();
    vec_groups.push(edc_group);

    // ACCOUNT OPERATORS
    let mut account_operators_group = Group::new();
    sid = domain.to_owned().to_uppercase();
    sid.push_str("-S-1-5-32-548");
    let mut name = "ACCOUNT OPERATORS@".to_owned();
    name.push_str(&domain.to_uppercase());
    
    *account_operators_group.object_identifier_mut() = sid;
    *account_operators_group.properties_mut().name_mut() = name;
    *account_operators_group.properties_mut().highvalue_mut() = true;
    *account_operators_group.properties_mut().domain_mut() = domain.to_owned();
    *account_operators_group.properties_mut().domainsid_mut() = domain_sid.to_owned();
    vec_groups.push(account_operators_group);

    // WINDOWS AUTHORIZATION ACCESS GROUP
    let mut waag_group = Group::new();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-32-560");
    let mut name = "WINDOWS AUTHORIZATION ACCESS GROUP@".to_owned();
    name.push_str(&domain.to_uppercase());
    *waag_group.object_identifier_mut() = sid;
    *waag_group.properties_mut().name_mut() = name;
    *waag_group.properties_mut().domainsid_mut() = domain_sid.to_owned();
    vec_groups.push(waag_group);

    // EVERYONE
    let mut everyone_group = Group::new();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-1-0");
    let mut name = "EVERYONE@".to_owned();
    name.push_str(&domain.to_uppercase());

    let mut vec_everyone_members: Vec<Member> = Vec::new();
    let mut member_id = member_sid.to_owned();
    member_id.push_str("-515");
    *template_member.object_identifier_mut() = member_id.to_owned();
    *template_member.object_type_mut() = "Group".to_string();
    vec_everyone_members.push(template_member.to_owned());

    member_id = member_sid.to_owned();
    member_id.push_str("-513");
    *template_member.object_identifier_mut() = member_id.to_owned();
    *template_member.object_type_mut() = "Group".to_string();
    vec_everyone_members.push(template_member.to_owned());

    *everyone_group.object_identifier_mut() = sid;
    *everyone_group.properties_mut().name_mut() = name;
    *everyone_group.properties_mut().domain_mut() = domain.to_owned();
    *everyone_group.properties_mut().domainsid_mut() = domain_sid.to_owned();
    *everyone_group.members_mut() = vec_everyone_members;
    vec_groups.push(everyone_group);

    // AUTHENTICATED USERS
    let mut auth_users_group = Group::new();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-11");
    let mut name = "AUTHENTICATED USERS@".to_owned();
    name.push_str(&domain.to_uppercase());

    let mut vec_auth_users_members: Vec<Member> = Vec::new();
    member_id = member_sid.to_owned();
    member_id.push_str("-515");
    *template_member.object_identifier_mut() = member_id.to_owned();
    *template_member.object_type_mut() = "Group".to_string();
    vec_auth_users_members.push(template_member.to_owned());

    member_id = member_sid.to_owned();
    member_id.push_str("-513");
    *template_member.object_identifier_mut() = member_id.to_owned();
    *template_member.object_type_mut() = "Group".to_string();
    vec_auth_users_members.push(template_member.to_owned());

    *auth_users_group.object_identifier_mut() = sid;
    *auth_users_group.properties_mut().name_mut() = name;
    *auth_users_group.properties_mut().domain_mut() = domain.to_owned();
    *auth_users_group.members_mut() = vec_auth_users_members;
    *auth_users_group.properties_mut().domainsid_mut() = domain_sid.to_owned();
    vec_groups.push(auth_users_group);

    // ADMINISTRATORS
    let mut administrators_group = Group::new();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-32-544");
    let mut name = "ADMINISTRATORS@".to_owned();
    name.push_str(&domain.to_uppercase());

    *administrators_group.object_identifier_mut() = sid;
    *administrators_group.properties_mut().name_mut() = name;
    *administrators_group.properties_mut().highvalue_mut() = true;
    *administrators_group.properties_mut().domain_mut() = domain.to_owned();
    *administrators_group.properties_mut().domainsid_mut() = domain_sid.to_owned();
    vec_groups.push(administrators_group);

    // PRE-WINDOWS 2000 COMPATIBLE ACCESS
    let mut pw2000ca_group = Group::new();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-32-554");
    let mut name = "PRE-WINDOWS 2000 COMPATIBLE ACCESS@".to_owned();
    name.push_str(&domain.to_uppercase());
            
    *pw2000ca_group.object_identifier_mut() = sid;
    *pw2000ca_group.properties_mut().name_mut() = name;
    *pw2000ca_group.properties_mut().domain_mut() = domain.to_owned();
    *pw2000ca_group.properties_mut().domainsid_mut() = domain_sid.to_owned();
    vec_groups.push(pw2000ca_group);    

    // INTERACTIVE
    let mut interactive_group = Group::new();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-4");
    let mut name = "INTERACTIVE@".to_owned();
    name.push_str(&domain.to_uppercase());

    *interactive_group.object_identifier_mut() = sid;
    *interactive_group.properties_mut().name_mut() = name;
    *interactive_group.properties_mut().domain_mut() = domain.to_owned();
    *interactive_group.properties_mut().domainsid_mut() = domain_sid.to_owned();
    vec_groups.push(interactive_group);

    // PRINT OPERATORS
    let mut print_operators_group = Group::new();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-32-550");
    let mut name = "PRINT OPERATORS@".to_owned();
    name.push_str(&domain.to_uppercase());
            
    *print_operators_group.object_identifier_mut() = sid;
    *print_operators_group.properties_mut().name_mut() = name;
    *print_operators_group.properties_mut().highvalue_mut() = true;
    *print_operators_group.properties_mut().domain_mut() = domain.to_owned();
    *print_operators_group.properties_mut().domainsid_mut() = domain_sid.to_owned();
    vec_groups.push(print_operators_group); 

    // TERMINAL SERVER LICENSE SERVERS
    let mut tsls_group = Group::new();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-32-561");
    let mut name = "TERMINAL SERVER LICENSE SERVERS@".to_owned();
    name.push_str(&domain.to_uppercase());
            
    *tsls_group.object_identifier_mut() = sid;
    *tsls_group.properties_mut().name_mut() = name;
    *tsls_group.properties_mut().domain_mut() = domain.to_owned();
    *tsls_group.properties_mut().domainsid_mut() = domain_sid.to_owned();
    vec_groups.push(tsls_group); 

    // INCOMING FOREST TRUST BUILDERS
    let mut iftb_group = Group::new();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-32-557");
    let mut name = "INCOMING FOREST TRUST BUILDERS@".to_owned();
    name.push_str(&domain.to_uppercase());
            
    *iftb_group.object_identifier_mut() = sid;
    *iftb_group.properties_mut().name_mut() = name;
    *iftb_group.properties_mut().domain_mut() = domain.to_owned();
    *iftb_group.properties_mut().domainsid_mut() = domain_sid.to_owned();
    vec_groups.push(iftb_group); 
 
    // THIS ORGANIZATION 
    let mut this_organization_group = Group::new();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-15");
    let mut name = "THIS ORGANIZATION@".to_owned();
    name.push_str(&domain.to_uppercase());
            
    *this_organization_group.object_identifier_mut() = sid;
    *this_organization_group.properties_mut().name_mut() = name;
    *this_organization_group.properties_mut().domain_mut() = domain.to_owned();
    *this_organization_group.properties_mut().domainsid_mut() = domain_sid.to_owned();
    vec_groups.push(this_organization_group);
    Ok(())
}

/// Function to add default user
/// <https://github.com/fox-it/BloodHound.py/blob/645082e3462c93f31b571db945cde1fd7b837fb9/bloodhound/enumeration/memberships.py#L411>
pub fn add_default_users(
    vec_users: &mut Vec<User>,
    domain: String
) -> Result<(), Box<dyn Error>> {
    // NT AUTHORITY
    let mut ntauthority_user = User::new();
    let mut sid = domain.to_uppercase();
    sid.push_str("-S-1-5-20");
    let mut name = "NT AUTHORITY@".to_owned();
    name.push_str(&domain.to_uppercase());
    *ntauthority_user.properties_mut().name_mut() = name;
    *ntauthority_user.object_identifier_mut() = sid;

    if let Some(first_user) = vec_users.get(0) {
        *ntauthority_user.properties_mut().domainsid_mut() = first_user.properties().domainsid().to_string();
    } else {
        error!("vec_users is empty, skipping domain SID assignment");
    }

    vec_users.push(ntauthority_user);
    Ok(())
}

/// Build a reverse index from SID to DN once, so per-object lookups are O(1)
/// instead of an O(n) linear scan over `dn_sid`. `dn_sid` values (SIDs) are
/// effectively unique; when a SID maps to several DNs the first one wins, which
/// matches the previous `.find()` behaviour.
fn build_sid_to_dn(dn_sid: &HashMap<String, String>) -> HashMap<&str, &str> {
    let mut sid_to_dn: HashMap<&str, &str> = HashMap::with_capacity(dn_sid.len());
    for (dn, sid) in dn_sid {
        // When a SID maps to several DNs, keep the lexicographically smallest so
        // the choice is deterministic instead of dependent on HashMap iteration
        // order (which otherwise makes e.g. ContainedBy vary run-to-run).
        sid_to_dn
            .entry(sid.as_str())
            .and_modify(|existing| {
                if dn.as_str() < *existing {
                    *existing = dn.as_str();
                }
            })
            .or_insert(dn.as_str());
    }
    sid_to_dn
}

/// The bytes of `s` in reverse order, for the ChildObjects automaton.
///
/// DNs in a domain share long suffixes (`...,OU=X,DC=CORP,DC=COM`). Reversed,
/// those suffixes become shared prefixes, which the automaton's trie stores
/// once, so it is built with far fewer states and much less memory.
///
/// The matches are the same: a byte string occurs in another exactly when its
/// reverse occurs in the other's reverse. This is a statement about bytes, so
/// it holds for multi-byte UTF-8 names too; the reversed bytes aren't valid
/// UTF-8, but the automaton compares bytes, not characters, and the search was
/// already a byte-substring search. Only the match offsets change, and only
/// the matched patterns are used.
fn reversed(s: &str) -> Vec<u8> {
    s.bytes().rev().collect()
}

/// `reversed`, into a buffer that is reused from one entry to the next.
fn reverse_into(buf: &mut Vec<u8>, s: &str) {
    buf.clear();
    buf.extend(s.bytes().rev());
}

/// This function is to push user SID in ChildObjects v2
pub fn add_childobjects_members<T: LdapObject + Send>(
    vec_replaced: &mut [T],
    dn_sid: &HashMap<String, String>,
    sid_type: &HashMap<String, String>,
) -> Result<(), Box<dyn Error>> {
    // Reverse index SID -> DN, built once (was an O(n) scan per object).
    let sid_to_dn = build_sid_to_dn(dn_sid);

    // Uppercase every DN a single time instead of once per object. The old code
    // re-allocated an uppercased copy of every `dn_sid` key for every object,
    // which was the O(n^2) allocation storm behind the multi-GB RAM use.
    let dn_upper: Vec<(String, &String)> =
        dn_sid.iter().map(|(dn, sid)| (dn.to_uppercase(), sid)).collect();

    // Get the DN and name of each object
    let dns: Vec<String> = vec_replaced
        .iter()
        .map(|object| {
            let sid = object.get_object_identifier().to_uppercase();
            sid_to_dn
                .get(sid.as_str())
                .map(|dn| dn.to_string())
                .unwrap_or(sid)
        })
        .collect();
    let names: Vec<String> = dns
        .iter()
        .map(|dn| get_name_from_full_distinguishedname(dn))
        .collect();

    // An entry is a candidate child of every object whose DN it contains. One
    // automaton over all the DNs finds them in a single pass over each entry,
    // instead of one substring test per (object, entry) pair. Objects that
    // share a DN share a pattern.
    let mut pattern_ids: HashMap<&str, usize> = HashMap::new();
    let mut patterns: Vec<&str> = Vec::new();
    let mut owners: Vec<Vec<usize>> = Vec::new();
    for (i, dn) in dns.iter().enumerate() {
        let id = *pattern_ids.entry(dn).or_insert_with(|| {
            patterns.push(dn);
            owners.push(Vec::new());
            patterns.len() - 1
        });
        owners[id].push(i);
    }
    // Both the DNs and the upper-cased entries are reversed, see `reversed`.
    // Only fails past the automaton's size limit (about 2^31 states).
    let ac = AhoCorasick::new(patterns.iter().map(|dn| reversed(dn)))?;

    // Entries are independent; match them across all CPU cores. A candidate is
    // kept, as before, when the entry's second RDN is the object's name, the
    // entry isn't the object itself, and the entry's SID isn't empty. Each
    // rayon task reverses its entries into one reused buffer.
    let longest = dn_upper.iter().map(|(dn, _)| dn.len()).max().unwrap_or(0);
    let mut pairs: Vec<(usize, usize)> = dn_upper
        .par_iter()
        .enumerate()
        .map_init(
            || Vec::with_capacity(longest),
            |haystack, (entry, (dn_object_upper, value_sid))| {
                let parent = dn_object_upper
                    .split(',')
                    .nth(1)
                    .and_then(|s| s.split('=').nth(1));
                match parent {
                    Some(parent) if !value_sid.is_empty() => {
                        reverse_into(haystack, dn_object_upper);
                        ac.find_overlapping_iter(&*haystack)
                            .flat_map(|m| &owners[m.pattern().as_usize()])
                            .filter(|&&o| names[o] == parent && *dn_object_upper != dns[o])
                            .map(|&o| (o, entry))
                            .collect()
                    }
                    _ => Vec::new(),
                }
            },
        )
        .flatten_iter()
        .collect();
    // Children of each object in dn_sid order, each listed once, as before.
    pairs.par_sort_unstable();
    pairs.dedup();

    let mut direct_members: Vec<Vec<Member>> = vec![Vec::new(); vec_replaced.len()];
    for (object, entry) in pairs {
        let value_sid = dn_upper[entry].1;
        let mut member = Member::new();
        *member.object_identifier_mut() = value_sid.clone();
        *member.object_type_mut() = sid_type.get(value_sid).unwrap_or(value_sid).to_string();
        direct_members[object].push(member);
    }
    for (object, members) in vec_replaced.iter_mut().zip(direct_members) {
        object.set_child_objects(members);
    }

    Ok(())
}

/// This function is to push user SID in ChildObjects for Ou v2
pub fn add_childobjects_members_for_ou(
    vec_replaced: &mut [Ou],
    dn_sid: &HashMap<String, String>,
    sid_type: &HashMap<String, String>,
) -> Result<(), Box<dyn Error>> {
    // Progress bar setup
    let total = vec_replaced.len();
    let pb = ProgressBar::new(total as u64);

    // Cache common values to avoid repeated allocations
    let null = "NULL".to_string();

    for (count, object) in vec_replaced.iter_mut().enumerate() {
        // Update progress bar periodically
        if count % (total / 100).max(1) == 0 {
            pb.set_position(count as u64);
        }

        let mut direct_members = Vec::new();
        let mut affected_computers = Vec::new();

        // Fetch properties of the current object
        let dn = object.properties().distinguishedname();
        let mut name = object.properties().name().to_owned();
        let sid = dn_sid.get(dn).unwrap_or(&null);
        let otype = sid_type.get(sid).unwrap_or(&null);

        // Adjust the name if not a domain
        if otype != "Domain" {
            if let Some(first_part) = name.split('@').next() {
                name = first_part.to_string();
            }
        }

        // Process all dn_sid entries
        for (dn_object, value_sid) in dn_sid {
            let dn_object_upper = dn_object.to_uppercase();

            // Parse the "first" component of the DN
            let first = dn_object_upper
                .split(',')
                .nth(1)
                .and_then(|part| part.split('=').nth(1))
                .unwrap_or("");

            if otype != "Domain" {
                // For non-domain objects
                if dn_object_upper.contains(dn) && &dn_object_upper != dn && first == name {
                    let mut member = Member::new();
                    *member.object_identifier_mut() = value_sid.clone();
                    let object_type = sid_type.get(value_sid).unwrap_or(&null).to_string();
                    *member.object_type_mut() = object_type.clone();

                    direct_members.push(member.clone());

                    // Add computers to affected_computers if applicable
                    if object_type == "Computer" {
                        affected_computers.push(member);
                    }
                }
            } else {
                // For domain objects
                if let Some(cn) = name.split('.').next() {
                    if first.contains(cn) {
                        let mut member = Member::new();
                        *member.object_identifier_mut() = value_sid.clone();
                        *member.object_type_mut() = sid_type.get(value_sid).unwrap_or(&null).to_string();
                        direct_members.push(member);
                    }
                }
            }
        }

        // Set child objects and GPO changes for OUs
        *object.child_objects_mut() = direct_members;
        if otype == "OU" {
            let mut gpo_changes = GPOChange::new();
            *gpo_changes.affected_computers_mut() = affected_computers;
            *object.gpo_changes_mut() = gpo_changes;
        }
    }

    pb.finish_and_clear();
    Ok(())
}

/// This function checks GUID for all Gplinks and replaces them with the correct GUIDs
pub fn replace_guid_gplink<T: LdapObject + Send>(
    vec_replaced: &mut [T],
    dn_sid: &HashMap<String, String>,
) -> Result<(), Box<dyn Error>> {
    // Distinct GUIDs of all links.
    let mut guid_ids: HashMap<String, usize> = HashMap::new();
    for link in vec_replaced.iter().flat_map(|object| object.get_links()) {
        let next = guid_ids.len();
        guid_ids.entry(link.guid().to_owned()).or_insert(next);
    }
    if guid_ids.is_empty() {
        return Ok(());
    }
    let mut guids = vec![""; guid_ids.len()];
    for (guid, &id) in &guid_ids {
        guids[id] = guid;
    }

    // A link takes the value of the first dn_sid key, in iteration order, that
    // contains its GUID. Walk the keys once with an automaton over all GUIDs,
    // instead of scanning the keys once per link. Building it only fails past
    // its size limit (about 2^31 states).
    let ac = AhoCorasick::new(&guids)?;
    let mut first: Vec<Option<&String>> = vec![None; guids.len()];
    let mut missing = guids.len();
    for (key, value) in dn_sid {
        if missing == 0 {
            break;
        }
        for m in ac.find_overlapping_iter(key) {
            let slot = &mut first[m.pattern().as_usize()];
            if slot.is_none() {
                *slot = Some(value);
                missing -= 1;
            }
        }
    }

    // Objects are independent; process them across all CPU cores.
    vec_replaced.par_iter_mut().for_each(|object| {
        // Process links if they exist
        if !object.get_links().is_empty() {
            // Replace GUIDs in links
            let updated_links: Vec<Link> = object
                .get_links()
                .iter()
                .map(|link| {
                    let mut new_link = link.clone(); // Clone the Link to create a new instance
                    if let Some(new_guid) = first[guid_ids[link.guid()]] {
                        *new_link.guid_mut() = new_guid.to_owned();
                    }
                    new_link
                })
                .collect();

            // Update the object's links
            object.set_links(updated_links);
        }
    });

    Ok(())
}

/// This function pushes computer SIDs into the domain's GPO changes v2
pub fn add_affected_computers(
    vec_domains: &mut [Domain],
    sid_type: &HashMap<String, String>,
) -> Result<(), Box<dyn Error>> {
    // Filter only "Computer" SIDs and map them to Member objects
    let vec_affected_computers: Vec<Member> = sid_type
        .iter()
        .filter(|&(_, obj_type)| obj_type == "Computer")
        .map(|(sid, _)| {
            let mut member = Member::new();
            *member.object_type_mut() = "Computer".to_string();
            *member.object_identifier_mut() = sid.clone();
            member
        })
        .collect();

    // Update the GPO changes of the first domain
    if let Some(domain) = vec_domains.get_mut(0) {
        let mut gpo_changes = GPOChange::new();
        *gpo_changes.affected_computers_mut() = vec_affected_computers;
        *domain.gpo_changes_mut() = gpo_changes;
    }
    Ok(())
}

/// This function pushes computer SIDs into GPO changes for each OU
pub fn add_affected_computers_for_ou(
    vec_ous: &mut [Ou],
    dn_sid: &HashMap<String, String>,
    sid_type: &HashMap<String, String>,
) -> Result<(), Box<dyn Error>> {
    // Group every computer under its parent DN a single time, so each OU is an
    // O(1) lookup instead of a full scan over all computers (was O(OUs*computers)).
    let mut computers_by_parent: HashMap<String, Vec<Member>> = HashMap::new();
    for (dn, sid) in dn_sid {
        if sid_type.get(sid).map(|t| t == "Computer").unwrap_or(false) {
            let parent = get_contained_by_name_from_distinguishedname(
                &get_cn_object_name_from_full_distinguishedname(dn),
                dn,
            );
            let mut member = Member::new();
            *member.object_identifier_mut() = sid.to_string();
            *member.object_type_mut() = "Computer".to_string();
            computers_by_parent.entry(parent).or_default().push(member);
        }
    }

    // Map each OU's identifier to its DN, using a reverse index built once
    // instead of scanning `dn_sid` per OU.
    let sid_to_dn = build_sid_to_dn(dn_sid);

    // For each OU, attach the pre-grouped affected computers (empty list when
    // none, matching the previous behaviour of always setting gpo_changes).
    for ou in vec_ous.iter_mut() {
        let Some(ou_dn) = sid_to_dn.get(ou.get_object_identifier().as_str()) else {
            continue;
        };
        let affected = computers_by_parent.get(*ou_dn).cloned().unwrap_or_default();
        let mut gpo_changes = GPOChange::new();
        *gpo_changes.affected_computers_mut() = affected;
        *ou.gpo_changes_mut() = gpo_changes;
    }
    Ok(())
}

/// This function replaces FQDN by SID in users' SPNTargets or computers' AllowedToDelegate
pub fn replace_fqdn_by_sid<T: LdapObject + Send>(
    object_type: Type,
    vec_src: &mut [T],
    fqdn_sid: &HashMap<String, String>,
) -> Result<(), Box<dyn Error>> {
    // Objects are independent and `fqdn_sid` is read-only, so process across all
    // CPU cores.
    match object_type {
        Type::User => {
            vec_src.par_iter_mut().for_each(|obj| {
                // Process SPNTargets
                for target in obj.get_spntargets_mut().iter_mut() {
                    let sid = fqdn_sid
                        .get(target.computer_sid())
                        .unwrap_or_else(|| target.computer_sid());
                    *target.computer_sid_mut() = sid.to_string();
                }

                // Process AllowedToDelegate
                for target in obj.get_allowed_to_delegate_mut().iter_mut() {
                    let sid = fqdn_sid
                        .get(target.object_identifier())
                        .unwrap_or_else(|| target.object_identifier());
                    *target.object_identifier_mut() = sid.to_string();
                }
            });
        }
        Type::Computer => {
            vec_src.par_iter_mut().for_each(|obj| {
                // Process AllowedToDelegate
                for delegate in obj.get_allowed_to_delegate_mut().iter_mut() {
                    let sid = fqdn_sid
                        .get(delegate.object_identifier())
                        .unwrap_or_else(|| delegate.object_identifier());
                    *delegate.object_identifier_mut() = sid.to_string();
                }
            });
        }
        _ => {}
    }

    Ok(())
}

/// This function checks and replaces object names by SIDs in group members v2
pub fn replace_sid_members(
    vec_groups: &mut [Group],
    dn_sid: &HashMap<String, String>,
    sid_type: &HashMap<String, String>,
    vec_trusts: &[Trust],
) -> Result<(), Box<dyn Error>> {
    // Unresolved members keep an unknown type; let BloodHound decide.
    let default_type = "Base".to_string();   // was "Group"
    
    // Groups are independent and the maps/trusts are read-only, so resolve
    // members across all CPU cores.
    vec_groups.par_iter_mut().for_each(|group| {
        for member in group.members_mut() {
            let member_dn = member.object_identifier();

            // 1) Skip clearly invalid entries
            if member_dn.trim().is_empty() || member_dn.eq_ignore_ascii_case("SID") {
                error!("Skipping empty/invalid member DN in group");
                continue;
            }

            // 2) Try to resolve via dn_sid
            if let Some(sid) = dn_sid.get(member_dn) {
                if !sid.is_empty() && sid != "NULL" {
                    let type_object =
                        sid_type.get(sid).cloned().unwrap_or_else(|| default_type.clone());
                    *member.object_identifier_mut() = sid.clone();
                    *member.object_type_mut() = type_object;
                    continue;
                }
            }

            // 3) Fallback: try trusts
            match sid_maker_from_another_domain(vec_trusts, member_dn) {
                Ok(generated_sid) if !generated_sid.is_empty() => {
                    *member.object_identifier_mut() = generated_sid;
                    *member.object_type_mut() = default_type.clone();
                }
                Ok(_) => {
                    error!("Could not resolve SID for member DN: {}", member_dn);
                }
                Err(e) => {
                    error!("Failed to resolve member DN {}: {}", member_dn, e);
                }
            }
        }
    });

    Ok(())
}

/// Make the SID from domain present in trust v2
fn sid_maker_from_another_domain(
    vec_trusts: &[Trust],
    object_identifier: &String,
) -> Result<String, Box<dyn Error>> {
    // Regex for SID matching, compiled once instead of on every call.
    static SID_REGEX: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"S-[0-9]+-[0-9]+-[0-9]+(?:-[0-9]+)+").unwrap());
    let sid_regex = &*SID_REGEX;

    // Check if the object_identifier matches any trusted domain
    for trust in vec_trusts {
        let ldap_dc = prepare_ldap_dc(trust.target_domain_name());
        if object_identifier.contains(&ldap_dc[0]) {
            let id = get_id_from_objectidentifier(object_identifier)?;
            return Ok(format!("{}{}", trust.target_domain_name(), id))
        }
    }

    // Check if object_identifier contains an SID
    if object_identifier.contains("CN=S-") {
        if let Some(capture) = sid_regex.captures(object_identifier).and_then(|cap| cap.get(0)) {
            return Ok(capture.as_str().to_owned())
        }
    }

    // Default case: return the object_identifier as-is
    Ok(object_identifier.to_string())
}

// Get id from objectidentifier for all common group (Administrators ...) v2
// https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
fn get_id_from_objectidentifier(
    object_identifier: &str
) -> Result<String, Box<dyn Error>> {

    // Static mapping of built-in group names to their well-known RIDs.
    //
    // NOTE: the French-language entries are intentional and REQUIRED, not
    // untranslated text. On a French-locale Domain Controller the built-in
    // groups are returned by LDAP under their localized names (e.g. "Domain
    // Admins" is literally "Administrateurs du domaine"), so each RID is
    // matched from both its English and French display name. Removing the
    // French names would break well-known-SID resolution on French domains.
    // Additional locales can be added here following the same pattern.
    const NAME_TO_RID: [(&str, &str); 16] = [
        // -512  Domain Admins
        ("DOMAIN ADMINS", "-512"),
        ("ADMINISTRATEURS DU DOMAINE", "-512"),
        // -513  Domain Users
        ("DOMAIN USERS", "-513"),
        ("UTILISATEURS DU DOMAINE", "-513"),
        // -514  Domain Guests
        ("DOMAIN GUESTS", "-514"),
        ("INVITES DE DOMAINE", "-514"),
        // -515  Domain Computers
        ("DOMAIN COMPUTERS", "-515"),
        ("ORDINATEURS DE DOMAINE", "-515"),
        // -516  Domain Controllers
        ("DOMAIN CONTROLLERS", "-516"),
        ("CONTRÔLEURS DE DOMAINE", "-516"),
        // -517  Cert Publishers
        ("CERT PUBLISHERS", "-517"),
        ("EDITEURS DE CERTIFICATS", "-517"),
        // -518  Schema Admins
        ("SCHEMA ADMINS", "-518"),
        ("ADMINISTRATEURS DU SCHEMA", "-518"),
        // -519  Enterprise Admins
        ("ENTERPRISE ADMINS", "-519"),
        ("ADMINISTRATEURS DE L'ENTREPRISE", "-519"),
    ];

    // Iterate over the static array to find a match
    for (name, rid) in NAME_TO_RID.iter() {
        if object_identifier.contains(name) {
            return Ok(rid.to_string())
        }
    }

    // Default case if no match is found
    Ok("NULL_ID1".to_string())
}

/// This function push trust domain values in domain
pub fn add_trustdomain(
    vec_domains: &mut Vec<Domain>,
    vec_trusts: &mut [Trust]
) -> Result<(), Box<dyn Error>> {
    if !&vec_trusts[0].target_domain_sid().to_string().contains("SID") {
        let mut trusts: Vec<Trust> = Vec::new();
        for trust in vec_trusts {
            trusts.push(trust.to_owned());
            let mut new_domain = Domain::new();
            *new_domain.object_identifier_mut() = trust.target_domain_sid().to_string();
            *new_domain.properties_mut().name_mut() = trust.target_domain_name().to_string();
            *new_domain.properties_mut().domain_mut() = trust.target_domain_name().to_string();
            *new_domain.properties_mut().distinguishedname_mut() = domain_to_dc(trust.target_domain_name());
            *new_domain.properties_mut().highvalue_mut() = true;
            vec_domains.push(new_domain);
        }
        *vec_domains[0].trusts_mut() = trusts.to_owned();
    }
    Ok(())
}

/// This function checks PrincipalSID for all ACEs and adds the PrincipalType ("Group", "User", "Computer") v2
pub fn add_type_for_ace<T: LdapObject + Send>(
    object: &mut [T],
    sid_type: &HashMap<String, String>,
) -> Result<(), Box<dyn Error>> {
    // Default type for unmatched SIDs
    let default_type = "Group".to_string();

    // Each object's ACEs are independent and `sid_type` is read-only here, so
    // this is embarrassingly parallel: spread it across all CPU cores.
    object.par_iter_mut().for_each(|obj| {
        for ace in obj.get_aces_mut() {
            // Fetch the type from sid_type or use the default
            let type_object = sid_type
                .get(ace.principal_sid())
                .unwrap_or(&default_type)
                .clone();

            // Update the principal type
            *ace.principal_type_mut() = type_object;
        }
    });

    Ok(())
}

/// This function checks PrincipalSID for all AllowedToAct objects and adds the PrincipalType ("Group", "User", "Computer") v2
pub fn add_type_for_allowtedtoact(
    computer: &mut [Computer],
    sid_type: &HashMap<String, String>,
) -> Result<(), Box<dyn Error>> {
    // Default type for unmatched SIDs
    let default_type = "Computer".to_string();

    // Computers are independent; process them across all CPU cores.
    computer.par_iter_mut().for_each(|comp| {
        // Process all AllowedToAct objects
        for allowed in comp.allowed_to_act_mut() {
            let type_object = sid_type
                .get(allowed.object_identifier())
                .unwrap_or(&default_type)
                .clone();

            *allowed.object_type_mut() = type_object;
        }
    });

    Ok(())
}

/// This function checks PrincipalSID for all HasSIDHistory objects and adds the PrincipalType ("Group", "User", "Computer")
pub fn add_type_for_sidhistory(
    vec_users:     &mut [User],
    vec_groups:    &mut [Group],
    vec_computers: &mut [Computer],
    sid_type:      &HashMap<String, String>,
) -> Result<(), Box<dyn Error>> {
    let default_type = "Base".to_string();

    vec_users.par_iter_mut().for_each(|user| {
        for principal in user.has_sid_history_mut() {
            let type_object = sid_type
                .get(principal.object_identifier())
                .unwrap_or(&default_type)
                .clone();
            *principal.object_type_mut() = type_object;
        }
    });

    vec_groups.par_iter_mut().for_each(|group| {
        for principal in group.has_sid_history_mut() {
            let type_object = sid_type
                .get(principal.object_identifier())
                .unwrap_or(&default_type)
                .clone();
            *principal.object_type_mut() = type_object;
        }
    });

    vec_computers.par_iter_mut().for_each(|computer| {
        for principal in computer.has_sid_history_mut() {
            let type_object = sid_type
                .get(principal.object_identifier())
                .unwrap_or(&default_type)
                .clone();
            *principal.object_type_mut() = type_object;
        }
    });

    Ok(())
}

/// This function pushes user SID into ChildObjects for Ou v2
pub fn add_contained_by_for<T: LdapObject + Send>(
    vec_replaced: &mut [T],
    dn_sid: &HashMap<String, String>,
    sid_type: &HashMap<String, String>,
) -> Result<(), Box<dyn Error>> {
    // Default type for unmatched SIDs
    let default_type = "Group".to_string();

    // Reverse index SID -> DN, built once. This used to be an O(n) linear scan
    // over `dn_sid` *per object* (`dn_sid.iter().find_map(...)`), i.e. O(n^2)
    // over the whole dataset — the dominant hang on large domains.
    let sid_to_dn = build_sid_to_dn(dn_sid);

    // Each object is independent and the maps are read-only here, so fan the
    // work out across all CPU cores.
    vec_replaced.par_iter_mut().for_each(|object| {
        // Fetch SID and DN for the current object
        let sid = object.get_object_identifier();
        let Some(dn) = sid_to_dn.get(sid.as_str()).copied() else {
            return;
        };

        let otype = sid_type.get(sid).unwrap_or(&default_type);
        if otype != "Domain" {
            // Extract CN name and contained-by name
            let dn_owned = dn.to_string();
            let cn_name = get_cn_object_name_from_full_distinguishedname(&dn_owned);
            let contained_by_name = get_contained_by_name_from_distinguishedname(&cn_name, &dn_owned);

            // Check if the contained-by name exists in dn_sid
            if let Some(sid_contained_by) = dn_sid.get(&contained_by_name) {
                let type_contained_by = sid_type.get(sid_contained_by).unwrap_or(&default_type);

                // Create and set the contained_by Member
                let mut contained_by = Member::new();
                *contained_by.object_identifier_mut() = sid_contained_by.to_string();
                *contained_by.object_type_mut() = type_contained_by.to_string();
                object.set_contained_by(Some(contained_by));
            }
        }
    });

    Ok(())
}

/// Function to resolve the group linked to each issuance policy
/// (`msDS-OIDToGroupLink`, ESC13) from the collected objects.
pub fn add_group_link_for_issuancepolicies(
    vec_issuancepolicies: &mut [IssuancePolicie],
    dn_sid: &HashMap<String, String>,
    sid_type: &HashMap<String, String>,
) -> Result<(), Box<dyn Error>> {
    vec_issuancepolicies.par_iter_mut().for_each(|issuancepolicie| {
        issuancepolicie.resolve_group_link(dn_sid, sid_type);
    });
    Ok(())
}

/// Function to get name from DN
pub fn get_name_from_full_distinguishedname(dn_object: &str) -> String {
    // Example:
    // dn_object = CN=G0H4N,CN=USERS,DC=ESSOS,DC=LOCAL
    trace!("get_name_from_full_distinguishedname() {:?}",&dn_object);
    let split1 = dn_object.split(",");
    let vec1 = split1.collect::<Vec<&str>>();
    let split2 = vec1[0].split("=");
    let vec2 = split2.collect::<Vec<&str>>();
    let name = vec2[1].to_owned();
    // name = G0H4N
    name
}

/// Function to get CN=name from DN
fn get_cn_object_name_from_full_distinguishedname(dn_object: &String) -> String {
    // Example:
    // dn_object = CN=G0H4N,CN=USERS,DC=ESSOS,DC=LOCAL
    let name = dn_object.to_owned();
    let split = name.split(",");
    let vec = split.collect::<Vec<&str>>();
    let name = vec[0].to_owned();
    // name = CN=G0H4N
    name
}

/// Function to get first degree contained by name from DN
fn get_contained_by_name_from_distinguishedname(cn_name: &str, dn_object: &str) -> String {
    // Example:
    // dn_object = CN=G0H4N,CN=USERS,DC=ESSOS,DC=LOCAL
    let name = format!("{},",cn_name);
    let split = dn_object.split(&name);
    let vec = split.collect::<Vec<&str>>();
    let dn_contained_by = vec[1].to_owned();
    // dn_contained_by = CN=USERS,DC=ESSOS,DC=LOCAL
    dn_contained_by
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    
    use crate::json::checker::common::{
        get_name_from_full_distinguishedname,
        get_cn_object_name_from_full_distinguishedname,
        get_contained_by_name_from_distinguishedname
    };
    
    #[test]
    #[rustfmt::skip]
    pub fn test_get_name_from_full_distinguishedname() {
        // Example:
        // dn_object = CN=G0H4N,CN=USERS,DC=ESSOS,DC=LOCAL
        let dn_object = "CN=G0H4N,CN=USERS,DC=ESSOS,DC=LOCAL".to_string();
        let cn_name =  get_name_from_full_distinguishedname(&dn_object);
        println!("dn_object: {:?}",dn_object);
        println!("cn_name: {:?}",cn_name);
        assert_eq!(cn_name, "G0H4N".to_string());
    }

    #[test]
    #[rustfmt::skip]
    pub fn test_get_cn_object_name_from_full_distinguishedname() {
        // Example:
        // dn_object = CN=G0H4N,CN=USERS,DC=ESSOS,DC=LOCAL
        let dn_object = "CN=G0H4N,CN=USERS,DC=ESSOS,DC=LOCAL".to_string();
        let cn_name =  get_cn_object_name_from_full_distinguishedname(&dn_object);
        println!("dn_object: {:?}",dn_object);
        println!("cn_name: {:?}",cn_name);
        assert_eq!(cn_name, "CN=G0H4N".to_string());
    }
    
    #[test]
    #[rustfmt::skip]
    pub fn test_get_contained_by_name_from_name() {
        // Example:
        // dn_object = CN=G0H4N,CN=USERS,DC=ESSOS,DC=LOCAL
        let dn_object = "CN=G0H4N,CN=USERS,DC=ESSOS,DC=LOCAL".to_string();
        let cn_name = "CN=G0H4N".to_string();
        let contained_by_dn =  get_contained_by_name_from_distinguishedname(&cn_name, &dn_object);
        println!("dn_object: {:?}",dn_object);
        println!("contained_by_dn: {:?}",contained_by_dn);
        assert_eq!(contained_by_dn, "CN=USERS,DC=ESSOS,DC=LOCAL".to_string());
    }
}

#[cfg(test)]
mod substring_scan_tests {
    use std::collections::{BTreeSet, HashMap};

    use aho_corasick::AhoCorasick;

    use crate::json::checker::common::{
        add_childobjects_members, build_sid_to_dn, get_name_from_full_distinguishedname,
        replace_guid_gplink, reversed,
    };
    use crate::objects::common::{LdapObject, Link, Member};
    use crate::objects::ou::Ou;

    /// `add_childobjects_members` as of 2.5.27: a substring test of every
    /// `dn_sid` entry against every object.
    fn reference_childobjects<T: LdapObject>(
        vec_replaced: &mut [T],
        dn_sid: &HashMap<String, String>,
        sid_type: &HashMap<String, String>,
    ) {
        let sid_to_dn = build_sid_to_dn(dn_sid);
        let dn_upper: Vec<(String, &String)> = dn_sid
            .iter()
            .map(|(dn, sid)| (dn.to_uppercase(), sid))
            .collect();
        for object in vec_replaced.iter_mut() {
            let sid = object.get_object_identifier().to_uppercase();
            let dn: &str = sid_to_dn.get(sid.as_str()).copied().unwrap_or(sid.as_str());
            let name = get_name_from_full_distinguishedname(dn);
            let direct_members: Vec<Member> = dn_upper
                .iter()
                .filter_map(|(dn_object_upper, value_sid)| {
                    if dn_object_upper.contains(dn)
                        && dn_object_upper.as_str() != dn
                        && dn_object_upper
                            .split(',')
                            .nth(1)
                            .and_then(|s| s.split('=').nth(1))
                            == Some(name.as_str())
                    {
                        let mut member = Member::new();
                        *member.object_identifier_mut() = (*value_sid).clone();
                        *member.object_type_mut() =
                            sid_type.get(*value_sid).unwrap_or(value_sid).to_string();
                        if !member.object_identifier().is_empty() {
                            return Some(member);
                        }
                    }
                    None
                })
                .collect();
            object.set_child_objects(direct_members);
        }
    }

    /// `replace_guid_gplink` as of 2.5.27: a scan of `dn_sid` per link.
    fn reference_gplink<T: LdapObject>(vec_replaced: &mut [T], dn_sid: &HashMap<String, String>) {
        for object in vec_replaced.iter_mut() {
            let links: Vec<Link> = object
                .get_links()
                .iter()
                .map(|link| {
                    let mut new_link = link.clone();
                    if let Some(new_guid) = dn_sid
                        .iter()
                        .find(|(key, _)| key.contains(link.guid()))
                        .map(|(_, guid)| guid.to_owned())
                    {
                        *new_link.guid_mut() = new_guid;
                    }
                    new_link
                })
                .collect();
            object.set_links(links);
        }
    }

    fn ou(id: &str, links: &[&str]) -> Ou {
        let mut v = serde_json::to_value(Ou::new()).unwrap();
        v["ObjectIdentifier"] = id.into();
        let mut ou: Ou = serde_json::from_value(v).unwrap();
        ou.set_links(
            links
                .iter()
                .map(|g| Link::new(false, g.to_string()))
                .collect(),
        );
        ou
    }

    fn json(v: &[Ou]) -> serde_json::Value {
        serde_json::to_value(v).unwrap()
    }

    /// Runs both versions on copies of `objects` with the same map instance
    /// (so the same iteration order) and compares the JSON output.
    fn same_as_reference(
        objects: Vec<Ou>,
        dn_sid: &HashMap<String, String>,
        sid_type: &HashMap<String, String>,
    ) -> serde_json::Value {
        let mut ours = objects.clone();
        let mut theirs = objects;
        add_childobjects_members(&mut ours, dn_sid, sid_type).unwrap();
        replace_guid_gplink(&mut ours, dn_sid).unwrap();
        reference_childobjects(&mut theirs, dn_sid, sid_type);
        reference_gplink(&mut theirs, dn_sid);
        let out = json(&ours);
        assert_eq!(out, json(&theirs));
        out
    }

    #[test]
    fn matches_the_substring_scan_on_edge_cases() {
        let gpo = "31B2F340-016D-11D2-945F-00C04FB984F9";
        let dn_sid: HashMap<String, String> = [
            (
                format!("CN={{{gpo}}},CN=POLICIES,CN=SYSTEM,DC=X,DC=Y"),
                "GPO-1",
            ),
            (
                format!("CN=MACHINE,CN={{{gpo}}},CN=POLICIES,CN=SYSTEM,DC=X,DC=Y"),
                "GPO-CHILD",
            ),
            (format!("CN=LONG{gpo}RUN,DC=X,DC=Y"), "LONG-RUN"),
            ("OU=A,DC=X,DC=Y".into(), "OU-A"),
            ("CN=U1,OU=A,DC=X,DC=Y".into(), "U1"),
            ("CN=U2,OU=A,OU=B,OU=A,DC=X,DC=Y".into(), "U2"),
            ("OU=A,OU=B,OU=A,DC=X,DC=Y".into(), "OU-A2"),
            ("CN=U3,CN=A,OU=A,DC=X,DC=Y".into(), "U3"),
            ("CN=E,OU=A,DC=X,DC=Y".into(), ""),
            ("OU=B,OU=A,DC=X,DC=Y".into(), "OU-B"),
            ("ou=c,dc=x,dc=y".into(), "OU-C"),
            ("CN=V,OU=C,DC=X,DC=Y".into(), "V"),
            ("DC=X,DC=Y".into(), "DOM"),
            ("CN=W,DC=X,DC=Y".into(), "W"),
            ("CN=Z,DC=X,DC=YY".into(), "Z"),
            ("DC=SOLO".into(), "SOLO"),
            ("CN=Q,DC=SOLO".into(), "Q"),
        ]
        .into_iter()
        .map(|(dn, sid)| (dn, sid.to_string()))
        .collect();
        let sid_type: HashMap<String, String> = [("U1", "User"), ("OU-B", "OU")]
            .into_iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect();
        let links = [
            gpo,
            "016D-11D2-945F-00C04FB984F9",
            "",
            "NOPE",
            "ou-a",
            "DC=X",
        ];
        let objects = ["OU-A", "OU-A2", "OU-B", "OU-C", "DOM", "ou-b", "SOLO"]
            .iter()
            .map(|id| ou(id, &links))
            .collect();
        let out = same_as_reference(objects, &dn_sid, &sid_type);

        // Not equal by being empty: OU=A lists U1 (and, like the substring
        // scan, U2 and U3), the domain lists W and Z, and the GPO link was
        // replaced by one of the three keys that contain the GUID.
        let kids = out[0]["ChildObjects"].to_string();
        for id in ["U1", "U2", "U3"] {
            assert!(kids.contains(&format!("\"{id}\"")), "{id}: {kids}");
        }
        let kids = out[4]["ChildObjects"].to_string();
        assert!(kids.contains("\"W\"") && kids.contains("\"Z\""), "{kids}");
        // A DN without a comma (substring test path).
        assert!(
            out[6]["ChildObjects"].to_string().contains("\"Q\""),
            "{}",
            out[6]
        );
        let first = out[0]["Links"][0]["GUID"].as_str().unwrap();
        assert!(
            ["GPO-1", "GPO-CHILD", "LONG-RUN"].contains(&first),
            "{first}"
        );
    }

    #[test]
    fn matches_the_substring_scan_on_a_generated_domain() {
        let base = "DC=CONTOSO,DC=LOCAL";
        let gpo = |i: usize| format!("{:08X}-0000-0000-0000-{:012X}", i, i);
        let mut dn_sid: HashMap<String, String> = HashMap::new();
        let mut objects = Vec::new();
        for i in 0..20 {
            dn_sid.insert(
                format!("CN={{{}}},CN=POLICIES,CN=SYSTEM,{base}", gpo(i)),
                format!("GPO-{i}"),
            );
        }
        dn_sid.insert(base.to_string(), "DOM".into());
        objects.push(ou("DOM", &[&gpo(0), &gpo(99)]));
        for s in 0..40 {
            // The same OU names under every site, and a nested OU named after
            // its site.
            let site = format!("OU=SITE{s},{base}");
            let mut ous = vec![(site.clone(), format!("SITE{s}"))];
            for sub in ["USERS", "COMPUTERS", "SERVERS"] {
                ous.push((format!("OU={sub},{site}"), format!("{sub}-{s}")));
            }
            ous.push((
                format!("OU=SITE{s},OU=SERVERS,{site}"),
                format!("INNER-{s}"),
            ));
            for (k, (dn, id)) in ous.iter().enumerate() {
                dn_sid.insert(dn.clone(), id.clone());
                objects.push(ou(id, &[&gpo((s + k) % 21)]));
                for leaf in 0..3 {
                    dn_sid.insert(format!("CN=LEAF{leaf},{dn}"), format!("{id}-L{leaf}"));
                }
            }
        }
        let sid_type = HashMap::new();
        let out = same_as_reference(objects, &dn_sid, &sid_type);
        let children: usize = out
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o["ChildObjects"].as_array().map_or(0, Vec::len))
            .sum();
        assert!(children > 500, "{children}");
    }

    /// Small deterministic generator (SplitMix64), so the test needs no seed
    /// handling and always checks the same domains.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }

        fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
            items[self.below(items.len())]
        }
    }

    #[test]
    fn matches_the_substring_scan_on_random_domains() {
        // Repeated names, escaped commas, and names whose upper case has a
        // different length (ß -> SS, ﬁ -> FI) or differs from the DN (ǅ, İ).
        // Upper-case DNs are the common case, and the only ones with children.
        let names = [
            "A", "A", "B", "B", "USERS", "USERS", "SRV", "X\\,Y", "X", "Y", "STRASSE", "FILE",
            "ǄX", "İST", "", "a", "Users", "Straße", "ﬁle", "ǅx", "i̇st",
        ];
        let kinds = ["OU", "OU", "CN", "CN", "DC", "ou"];
        let bases = ["DC=X,DC=Y", "dc=x,dc=y", "DC=SOLO", "DC=X,DC=YY"];
        let guids = [
            "31B2F340-016D-11D2-945F-00C04FB984F9",
            "6AC1786C-016F-11D2-945F-00C04FB984F9",
            "6ac1786c-016f-11d2-945f-00c04fb984f9",
            "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA",
            "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAB",
        ];
        let odd_links = [
            "",
            "016D-11D2",
            "{31B2F340-016D-11D2-945F-00C04FB984F9}",
            "DC=X",
            "A",
            "ß",
        ];
        let mut rng = Rng(101);

        for _ in 0..100 {
            let mut dn_sid: HashMap<String, String> = HashMap::new();
            let mut sid_type: HashMap<String, String> = HashMap::new();
            let sid_count = 3 + rng.below(80);
            let mut dns: Vec<String> = Vec::new();
            for _ in 0..rng.below(80) {
                // Mostly a child of an earlier DN, so names repeat at several
                // depths of the same tree.
                let mut dn = match dns.len() {
                    n if n > 0 && rng.below(4) != 0 => dns[rng.below(n)].clone(),
                    _ => rng.pick(&bases).to_string(),
                };
                for _ in 0..1 + rng.below(4) / 3 {
                    dn = format!("{}={},{dn}", rng.pick(&kinds), rng.pick(&names));
                }
                dns.push(dn.clone());
                match rng.below(8) {
                    0 => dn = format!("CN={{{}}},CN=POLICIES,{dn}", rng.pick(&guids)),
                    1 => dn = format!("CN=RUN{}{},{dn}", rng.pick(&guids), rng.pick(&guids)),
                    2 => dn = format!("CN={}", rng.pick(&names)),
                    _ => {}
                }
                // Several DNs can share a SID, and some SIDs are empty.
                let sid = match rng.below(10) {
                    0 => String::new(),
                    1 => format!("s-{}", rng.below(sid_count)),
                    _ => format!("S-{}", rng.below(sid_count)),
                };
                if rng.below(3) == 0 {
                    sid_type.insert(sid.clone(), rng.pick(&["User", "OU", "Computer"]).into());
                }
                dn_sid.insert(dn, sid);
            }

            // Objects are the SIDs of some entries (sometimes in another case),
            // or a DN used as identifier when no entry has that SID. An
            // identifier must resolve to a DN, as both versions assume.
            let sids: Vec<String> = dn_sid
                .values()
                .filter(|sid| dn_sid.values().any(|other| *other == sid.to_uppercase()))
                .cloned()
                .collect();
            let mut objects = Vec::new();
            for _ in 0..rng.below(40) {
                let id = match (rng.below(6), sids.is_empty()) {
                    (0, _) | (_, true) => format!("OU={},{}", rng.pick(&names), rng.pick(&bases)),
                    (1, false) => sids[rng.below(sids.len())].to_lowercase(),
                    _ => sids[rng.below(sids.len())].clone(),
                };
                let mut links = Vec::new();
                for _ in 0..rng.below(4) {
                    links.push(if rng.below(4) == 0 {
                        rng.pick(&odd_links)
                    } else {
                        rng.pick(&guids)
                    });
                }
                objects.push(ou(&id, &links));
            }
            same_as_reference(objects, &dn_sid, &sid_type);
        }
    }

    /// (pattern, entry) pairs found by an automaton over `patterns`, run on
    /// every entry, with or without reversing both.
    fn automaton_pairs(
        patterns: &[String],
        entries: &[String],
        reverse: bool,
    ) -> BTreeSet<(usize, usize)> {
        let bytes = |s: &String| {
            if reverse {
                reversed(s)
            } else {
                s.as_bytes().to_vec()
            }
        };
        let ac = AhoCorasick::new(patterns.iter().map(bytes)).unwrap();
        entries
            .iter()
            .enumerate()
            .flat_map(|(e, entry)| {
                ac.find_overlapping_iter(&bytes(entry))
                    .map(|m| (m.pattern().as_usize(), e))
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    #[test]
    fn reversed_automaton_finds_the_same_pairs() {
        // Multi-byte names, including ones that share bytes in different
        // orders (é = C3 A9, © = C2 A9, Ã = C3 83, é as e + U+0301), names
        // whose upper case changes length, and the empty name.
        let names = [
            "A", "USERS", "SRV", "X\\,Y", "Straße", "ﬁle", "ǅx", "İST", "é", "É", "e\u{301}", "©Ã",
            "Ã©", "ÃÃ", "日本", "本日", "Ωμέ", "🙂", "🙃🙂", "", "a",
        ];
        let kinds = ["OU", "CN", "DC", "ou"];
        let bases = ["DC=X,DC=Y", "dc=x,dc=y", "DC=É,DC=日本", "DC=SOLO"];
        let mut rng = Rng(103);
        let mut children = 0;

        for _ in 0..100 {
            let mut dns: Vec<String> = Vec::new();
            for _ in 0..rng.below(120) {
                let mut dn = match dns.len() {
                    n if n > 0 && rng.below(4) != 0 => dns[rng.below(n)].clone(),
                    _ => rng.pick(&bases).to_string(),
                };
                for _ in 0..1 + rng.below(3) {
                    dn = format!("{}={},{dn}", rng.pick(&kinds), rng.pick(&names));
                }
                dns.push(dn);
            }
            // As in `add_childobjects_members`: the patterns are object DNs as
            // they are, the entries are upper-cased before they are reversed.
            let patterns: Vec<String> = dns.iter().step_by(2).cloned().collect();
            let entries: Vec<String> = dns.iter().map(|dn| dn.to_uppercase()).collect();

            let forward = automaton_pairs(&patterns, &entries, false);
            assert_eq!(forward, automaton_pairs(&patterns, &entries, true));
            // Both are the substring test.
            let contains: BTreeSet<(usize, usize)> = (0..patterns.len())
                .flat_map(|p| (0..entries.len()).map(move |e| (p, e)))
                .filter(|&(p, e)| entries[e].contains(patterns[p].as_str()))
                .collect();
            assert_eq!(forward, contains);

            // And the whole pass agrees with the substring scan on these names.
            let dn_sid: HashMap<String, String> = dns
                .iter()
                .enumerate()
                .map(|(i, dn)| (dn.clone(), format!("S-{i}")))
                .collect();
            let objects = dns.iter().map(|dn| ou(&dn_sid[dn], &[])).collect();
            let out = same_as_reference(objects, &dn_sid, &HashMap::new());
            children += out
                .as_array()
                .unwrap()
                .iter()
                .map(|o| o["ChildObjects"].as_array().map_or(0, Vec::len))
                .sum::<usize>();
        }
        assert!(children > 100, "{children}");
    }
}
