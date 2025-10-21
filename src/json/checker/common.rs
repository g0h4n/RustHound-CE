use std::collections::HashMap;
use std::error::Error;

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
    common::{Member, GPOChange, LdapObject}
};
//use log::{info,debug,trace};
use crate::ldap::prepare_ldap_dc;
use crate::utils::format::domain_to_dc;
use crate::enums::regex::COMMON_RE1;
use indicatif::ProgressBar;
use log::trace;

/// Function to add default groups
/// <https://github.com/fox-it/BloodHound.py/blob/645082e3462c93f31b571db945cde1fd7b837fb9/bloodhound/enumeration/memberships.py#L411>
pub fn add_default_groups(
    vec_groups: &mut Vec<Group>,
    vec_computers: &[Computer],
    domain: String
) -> Result<(), Box<dyn Error>> {
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
                domain_sid = capture.get(0).map(|m| m.as_str().to_string()).unwrap_or_default();
            }
        }
    }

    *edc_group.object_identifier_mut() = sid;
    *edc_group.properties_mut().name_mut() = name;
    *edc_group.members_mut() = vec_members;
    vec_groups.push(edc_group);

    // ACCOUNT OPERATORS
    let mut account_operators_group = Group::new();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-32-548");
    let mut name = "ACCOUNT OPERATORS@".to_owned();
    name.push_str(&domain.to_uppercase());
    
    *account_operators_group.object_identifier_mut() = sid;
    *account_operators_group.properties_mut().name_mut() = name;
    *account_operators_group.properties_mut().highvalue_mut() = true;
    vec_groups.push(account_operators_group);

    // WINDOWS AUTHORIZATION ACCESS GROUP
    let mut waag_group = Group::new();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-32-560");
    let mut name = "WINDOWS AUTHORIZATION ACCESS GROUP@".to_owned();
    name.push_str(&domain.to_uppercase());
    *waag_group.object_identifier_mut() = sid;
    *waag_group.properties_mut().name_mut() = name;
    vec_groups.push(waag_group);

    // EVERYONE
    let mut everyone_group = Group::new();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-1-0");
    let mut name = "EVERYONE@".to_owned();
    name.push_str(&domain.to_uppercase());

    let mut vec_everyone_members: Vec<Member> = Vec::new();
    let mut member_id = domain_sid.to_owned();
    member_id.push_str("-515");
    *template_member.object_identifier_mut() = member_id.to_owned();
    *template_member.object_type_mut() = "Group".to_string();
    vec_everyone_members.push(template_member.to_owned());

    member_id = domain_sid.to_owned();
    member_id.push_str("-513");
    *template_member.object_identifier_mut() = member_id.to_owned();
    *template_member.object_type_mut() = "Group".to_string();
    vec_everyone_members.push(template_member.to_owned());

    *everyone_group.object_identifier_mut() = sid;
    *everyone_group.properties_mut().name_mut() = name;
    *everyone_group.members_mut() = vec_everyone_members;
    vec_groups.push(everyone_group);

    // AUTHENTICATED USERS
    let mut auth_users_group = Group::new();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-11");
    let mut name = "AUTHENTICATED USERS@".to_owned();
    name.push_str(&domain.to_uppercase());

    let mut vec_auth_users_members: Vec<Member> = Vec::new();
    member_id = domain_sid.to_owned();
    member_id.push_str("-515");
    *template_member.object_identifier_mut() = member_id.to_owned();
    *template_member.object_type_mut() = "Group".to_string();
    vec_auth_users_members.push(template_member.to_owned());

    member_id = domain_sid.to_owned();
    member_id.push_str("-513");
    *template_member.object_identifier_mut() = member_id.to_owned();
    *template_member.object_type_mut() = "Group".to_string();
    vec_auth_users_members.push(template_member.to_owned());

    *auth_users_group.object_identifier_mut() = sid;
    *auth_users_group.properties_mut().name_mut() = name;
    *auth_users_group.members_mut() = vec_auth_users_members;
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
    vec_groups.push(administrators_group);

    // PRE-WINDOWS 2000 COMPATIBLE ACCESS
    let mut pw2000ca_group = Group::new();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-32-554");
    let mut name = "PRE-WINDOWS 2000 COMPATIBLE ACCESS@".to_owned();
    name.push_str(&domain.to_uppercase());
            
    *pw2000ca_group.object_identifier_mut() = sid;
    *pw2000ca_group.properties_mut().name_mut() = name;
    vec_groups.push(pw2000ca_group);    

    // INTERACTIVE
    let mut interactive_group = Group::new();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-4");
    let mut name = "INTERACTIVE@".to_owned();
    name.push_str(&domain.to_uppercase());

    *interactive_group.object_identifier_mut() = sid;
    *interactive_group.properties_mut().name_mut() = name;
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
    vec_groups.push(print_operators_group); 

    // TERMINAL SERVER LICENSE SERVERS
    let mut tsls_group = Group::new();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-32-561");
    let mut name = "TERMINAL SERVER LICENSE SERVERS@".to_owned();
    name.push_str(&domain.to_uppercase());
            
    *tsls_group.object_identifier_mut() = sid;
    *tsls_group.properties_mut().name_mut() = name;
    vec_groups.push(tsls_group); 

    // INCOMING FOREST TRUST BUILDERS
    let mut iftb_group = Group::new();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-32-557");
    let mut name = "INCOMING FOREST TRUST BUILDERS@".to_owned();
    name.push_str(&domain.to_uppercase());
            
    *iftb_group.object_identifier_mut() = sid;
    *iftb_group.properties_mut().name_mut() = name;
    vec_groups.push(iftb_group); 
 
    // THIS ORGANIZATION 
    let mut this_organization_group = Group::new();
    sid = domain.to_uppercase();
    sid.push_str("-S-1-5-15");
    let mut name = "THIS ORGANIZATION@".to_owned();
    name.push_str(&domain.to_uppercase());
            
    *this_organization_group.object_identifier_mut() = sid;
    *this_organization_group.properties_mut().name_mut() = name;
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
    *ntauthority_user.properties_mut().domainsid_mut() = vec_users[0].properties().domainsid().to_string();
    vec_users.push(ntauthority_user);
    Ok(())
}

/// This function is to push user SID in ChildObjects v2
pub fn add_childobjects_members<T: LdapObject>(
    vec_replaced: &mut [T],
    dn_sid: &HashMap<String, String>,
    sid_type: &HashMap<String, String>,
) -> Result<(), Box<dyn Error>> {
    // Needed for progress bar stats
    let total = vec_replaced.len();
    let pb = ProgressBar::new(total as u64);

    // Iterate over the objects
    for (count, object) in vec_replaced.iter_mut().enumerate() {
        // Update progress bar periodically
        if count % (total / 100).max(1) == 0 {
            pb.set_position(count as u64);
        }

        // Get the SID, DN, and name of the current object
        let sid = object.get_object_identifier().to_uppercase();
        let dn = dn_sid
            .iter()
            .find(|(_, v)| **v == sid)
            .map(|(k, _)| k)
            .unwrap_or(&sid);
        let name = get_name_from_full_distinguishedname(dn);
        let _otype = sid_type.get(&sid).unwrap();

        // Filter direct members from dn_sid
        let direct_members: Vec<Member> = dn_sid
            .iter()
            .filter_map(|(dn_object, value_sid)| {
                let dn_object_upper = dn_object.to_uppercase();

                // Check if dn_object is related to the current object's DN
                if dn_object_upper.contains(dn)
                    && &dn_object_upper != dn
                    && dn_object_upper.split(',')
                        .nth(1)
                        .and_then(|s| s.split('=').nth(1))
                        == Some(&name)
                {
                    let mut member = Member::new();
                    *member.object_identifier_mut() = value_sid.clone();
                    *member.object_type_mut() = sid_type.get(value_sid).unwrap_or(&value_sid).to_string();
                    if !member.object_identifier().is_empty() {
                        return Some(member);
                    }
                }
                None
            })
            .collect();

        // Set direct members for the object
        object.set_child_objects(direct_members);
    }

    pb.finish_and_clear();
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
pub fn replace_guid_gplink<T: LdapObject>(
    vec_replaced: &mut [T],
    dn_sid: &HashMap<String, String>,
) -> Result<(), Box<dyn Error>> {
    // Progress bar setup
    let total = vec_replaced.len();
    let pb = ProgressBar::new(total as u64);

    // Iterate over the objects
    for (count, object) in vec_replaced.iter_mut().enumerate() {
        // Update progress bar periodically
        if count % (total / 100).max(1) == 0 {
            pb.set_position(count as u64);
        }

        // Process links if they exist
        if !object.get_links().is_empty() {
            // Replace GUIDs in links
            let updated_links: Vec<Link> = object
                .get_links()
                .iter()
                .map(|link| {
                    let mut new_link = link.clone(); // Clone the Link to create a new instance
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

            // Update the object's links
            object.set_links(updated_links);
        }
    }

    pb.finish_and_clear();
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
    // Filter all computers DN:SID in advance
    let dn_sid_filtered: Vec<(&String, &String)> = dn_sid
        .iter()
        .filter(|(_, sid)| sid_type.get(*sid).map(|t| t == "Computer").unwrap_or(false))
        .collect();

    // Map each OU's identifier to its DN
    let ou_dn_map: HashMap<String, String> = vec_ous
        .iter()
        .filter_map(|ou| {
            dn_sid
                .iter()
                .find_map(|(dn, sid)| {
                    if *sid == *ou.get_object_identifier() {
                        Some((ou.get_object_identifier().to_owned(), dn.clone()))
                    } else {
                        None
                    }
                })
        })
        .collect();

    // For each OU, add affected computers
    for ou in vec_ous.iter_mut() {
        if let Some(ou_dn) = ou_dn_map.get(ou.get_object_identifier()) {
            let vec_affected_computers: Vec<Member> = dn_sid_filtered
                .iter()
                .filter_map(|(dn, sid)| {
                    if get_contained_by_name_from_distinguishedname(
                        &get_cn_object_name_from_full_distinguishedname(dn),
                        dn,
                    ) == *ou_dn
                    {
                        let mut member = Member::new();
                        *member.object_identifier_mut() = sid.to_string();
                        *member.object_type_mut() = "Computer".to_string();
                        Some(member)
                    } else {
                        None
                    }
                })
                .collect();

            // Update GPO changes for the OU
            let mut gpo_changes = GPOChange::new();
            *gpo_changes.affected_computers_mut() = vec_affected_computers;
            *ou.gpo_changes_mut() = gpo_changes;
        }
    }
    Ok(())
}

/// This function replaces FQDN by SID in users' SPNTargets or computers' AllowedToDelegate
pub fn replace_fqdn_by_sid<T: LdapObject>(
    object_type: Type,
    vec_src: &mut [T],
    fqdn_sid: &HashMap<String, String>,
) -> Result<(), Box<dyn Error>> {
    // Progress bar setup
    let total = vec_src.len();
    let pb = ProgressBar::new(total as u64);

    // Process based on the object type
    match object_type {
        Type::User => {
            for (count, obj) in vec_src.iter_mut().enumerate() {
                // Update progress bar
                if count % (total / 100).max(1) == 0 {
                    pb.set_position(count as u64);
                }

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
            }
        }
        Type::Computer => {
            for (count, obj) in vec_src.iter_mut().enumerate() {
                // Update progress bar
                if count % (total / 100).max(1) == 0 {
                    pb.set_position(count as u64);
                }

                // Process AllowedToDelegate
                for delegate in obj.get_allowed_to_delegate_mut().iter_mut() {
                    let sid = fqdn_sid
                        .get(delegate.object_identifier())
                        .unwrap_or_else(|| delegate.object_identifier());
                    *delegate.object_identifier_mut() = sid.to_string();
                }
            }
        }
        _ => {}
    }

    pb.finish_and_clear();
    Ok(())
}

/// This function checks and replaces object names by SIDs in group members v2
pub fn replace_sid_members(
    vec_groups: &mut [Group],
    dn_sid: &HashMap<String, String>,
    sid_type: &HashMap<String, String>,
    vec_trusts: &[Trust],
) -> Result<(), Box<dyn Error>> {
    // Progress bar setup
    let total = vec_groups.len();
    let pb = ProgressBar::new(total as u64);

    // Default values
    let default_sid = "NULL".to_string();
    let default_type = "Group".to_string();

    // Iterate over groups
    for (count, group) in vec_groups.iter_mut().enumerate() {
        // Update progress bar periodically
        if count % (total / 100).max(1) == 0 {
            pb.set_position(count as u64);
        }

        // Process each member in the group
        for member in group.members_mut() {
            let member_dn = member.object_identifier();

            // Get the SID from dn_sid or check in trusts
            let sid = dn_sid.get(member_dn).unwrap_or(&default_sid);
            if sid == "NULL" {
                // Generate SID from another domain if not found
                let generated_sid = sid_maker_from_another_domain(vec_trusts, member_dn)?;
                *member.object_identifier_mut() = generated_sid.to_owned();
                *member.object_type_mut() = default_type.clone();
            } else {
                // Use the existing SID
                let type_object = sid_type.get(sid).unwrap_or(&default_type).to_owned();
                *member.object_identifier_mut() = sid.to_owned();
                *member.object_type_mut() = type_object;
            }
        }
    }

    pb.finish_and_clear();
    Ok(())
}

/// Make the SID from domain present in trust v2
fn sid_maker_from_another_domain(
    vec_trusts: &[Trust],
    object_identifier: &String,
) -> Result<String, Box<dyn Error>> {
    // Create the regex for SID matching
    let sid_regex = Regex::new(r"S-[0-9]+-[0-9]+-[0-9]+(?:-[0-9]+)+")?;

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

    // Static mapping of group names to RIDs
    const NAME_TO_RID: [(&str, &str); 16] = [
        ("DOMAIN ADMINS", "-512"),
        ("ADMINISTRATEURS DU DOMAINE", "-512"),
        ("DOMAIN USERS", "-513"),
        ("UTILISATEURS DU DOMAINE", "-513"),
        ("DOMAIN GUESTS", "-514"),
        ("INVITES DE DOMAINE", "-514"),
        ("DOMAIN COMPUTERS", "-515"),
        ("ORDINATEURS DE DOMAINE", "-515"),
        ("DOMAIN CONTROLLERS", "-516"),
        ("CONTRÔLEURS DE DOMAINE", "-516"),
        ("CERT PUBLISHERS", "-517"),
        ("EDITEURS DE CERTIFICATS", "-517"),
        ("SCHEMA ADMINS", "-518"),
        ("ADMINISTRATEURS DU SCHEMA", "-518"),
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
pub fn add_type_for_ace<T: LdapObject>(
    object: &mut [T],
    sid_type: &HashMap<String, String>,
) -> Result<(), Box<dyn Error>> {
    // Progress bar setup
    let total = object.len();
    let pb = ProgressBar::new(total as u64);

    // Default type for unmatched SIDs
    let default_type = "Group".to_string();

    // Iterate over each object
    for (count, obj) in object.iter_mut().enumerate() {
        // Update progress bar
        if count % (total / 100).max(1) == 0 {
            pb.set_position(count as u64);
        }

        // Get mutable reference to ACEs
        for ace in obj.get_aces_mut() {
            // Fetch the type from sid_type or use the default
            let type_object = sid_type
                .get(ace.principal_sid())
                .unwrap_or(&default_type)
                .clone();

            // Update the principal type
            *ace.principal_type_mut() = type_object;
        }
    }

    pb.finish_and_clear();
    Ok(())
}

/// This function checks PrincipalSID for all AllowedToAct objects and adds the PrincipalType ("Group", "User", "Computer") v2
pub fn add_type_for_allowtedtoact(
    computer: &mut [Computer],
    sid_type: &HashMap<String, String>,
) -> Result<(), Box<dyn Error>> {
    // Progress bar setup
    let total = computer.len();
    let pb = ProgressBar::new(total as u64);

    // Default type for unmatched SIDs
    let default_type = "Computer".to_string();

    // Iterate over all computers
    for (count, comp) in computer.iter_mut().enumerate() {
        // Update progress bar periodically
        if count % (total / 100).max(1) == 0 {
            pb.set_position(count as u64);
        }

        // Process all AllowedToAct objects
        for allowed in comp.allowed_to_act_mut() {
            let type_object = sid_type
                .get(allowed.object_identifier())
                .unwrap_or(&default_type)
                .clone();

            *allowed.object_type_mut() = type_object;
        }
    }

    pb.finish_and_clear();
    Ok(())
}

/// This function pushes user SID into ChildObjects for Ou v2
pub fn add_contained_by_for<T: LdapObject>(
    vec_replaced: &mut [T],
    dn_sid: &HashMap<String, String>, 
    sid_type: &HashMap<String, String>,
) -> Result<(), Box<dyn Error>> {
    // Progress bar setup
    let total = vec_replaced.len();
    let pb = ProgressBar::new(total as u64);

    // Default type for unmatched SIDs
    let default_type = "Group".to_string();

    for (count, object) in vec_replaced.iter_mut().enumerate() {
        // Update progress bar periodically
        if count % (total / 100).max(1) == 0 {
            pb.set_position(count as u64);
        }

        // Fetch SID and DN for the current object
        let sid = object.get_object_identifier();
        let dn = dn_sid.iter().find_map(|(key, value)| if value == sid { Some(key) } else { None });

        if let Some(dn) = dn {
            let otype = sid_type.get(sid).unwrap_or(&default_type);

            if otype != "Domain" {
                // Extract CN name and contained-by name
                let cn_name = get_cn_object_name_from_full_distinguishedname(dn);
                let contained_by_name = get_contained_by_name_from_distinguishedname(&cn_name, dn);

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
        }
    }

    pb.finish_and_clear();
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