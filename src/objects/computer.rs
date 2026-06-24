use serde_json::value::Value;
use serde::{Deserialize, Serialize};
use colored::Colorize;
use ldap3::SearchEntry;
use log::{info, debug, trace};
use std::collections::HashMap;
use std::error::Error;

use crate::enums::{OBJECT_SID_RE1, SID_PART1_RE1};
use crate::objects::common::{LdapObject, Session, AceTemplate, Member, SPNTarget, LocalGroup, Link, DCRegistryData};
use crate::utils::date::{convert_timestamp,string_to_epoch};
use crate::utils::crypto::convert_encryption_types;
use crate::enums::acl::parse_ntsecuritydescriptor;
use crate::enums::secdesc::LdapSid;
use crate::enums::sid::sid_maker;
use crate::enums::uacflags::get_flag;

use super::common::UserRight;

/// Computer structure
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Computer {
    #[serde(rename = "Properties")]
    properties: ComputerProperties,
    #[serde(rename = "Aces")]
    aces: Vec<AceTemplate>,
    #[serde(rename = "ObjectIdentifier")]
    object_identifier: String,
    #[serde(rename = "IsDeleted")]
    is_deleted: bool,
    #[serde(rename = "IsACLProtected")]
    is_acl_protected: bool,
    #[serde(rename = "ContainedBy")]
    contained_by: Option<Member>,

    #[serde(rename = "PrimaryGroupSID")]
    primary_group_sid: String,
    #[serde(rename = "AllowedToDelegate")]
    allowed_to_delegate: Vec<Member>,
    #[serde(rename = "AllowedToAct")]
    allowed_to_act: Vec<Member>,
    #[serde(rename = "HasSIDHistory")]
    has_sid_history: Vec<String>,
    #[serde(rename = "DumpSMSAPassword")]
    dump_smsa_password: Vec<Member>,
    
    #[serde(rename = "Sessions")]
    sessions: Session,
    #[serde(rename = "PrivilegedSessions")]
    privileged_sessions: Session,
    #[serde(rename = "RegistrySessions")]
    registry_sessions: Session,
    #[serde(rename = "LocalGroups")]
    local_groups: Vec<LocalGroup>,
    #[serde(rename = "UserRights")]
    users_rights: Vec<UserRight>,
    #[serde(rename = "DCRegistryData")]
    dcregistry_data: DCRegistryData,

    #[serde(rename = "IsDC")]
    is_dc: bool,
    #[serde(rename = "UnconstrainedDelegation")]
    unconstrained_delegation: bool,
    #[serde(rename = "DomainSID")]
    domain_sid: String,

    #[serde(rename = "Status")]
    status: Option<String>,
}

impl Computer {
    // New computer.
    pub fn new() -> Self { 
        Self { ..Default::default() } 
    }

    // Immutable access.
    pub fn properties(&self) -> &ComputerProperties {
        &self.properties
    }
    pub fn object_identifier(&self) -> &String {
        &self.object_identifier
    }
    pub fn allowed_to_act(&self) -> &Vec<Member> {
        &self.allowed_to_act
    }

    // Mutable access.
    pub fn allowed_to_act_mut(&mut self) -> &mut Vec<Member> {
        &mut self.allowed_to_act
    }

    /// Function to parse and replace value for computer object.
    /// <https://bloodhound.readthedocs.io/en/latest/further-reading/json.html#computers>
    pub fn parse(
        &mut self,
        result: SearchEntry,
        domain: &str,
        dn_sid: &mut HashMap<String, String>,
        sid_type: &mut HashMap<String, String>,
        fqdn_sid: &mut HashMap<String, String>,
        fqdn_ip: &mut HashMap<String, String>,
        domain_sid: &str,
        schema_guid_map: &HashMap<String, String>,
    ) -> Result<(), Box<dyn Error>> {
        let result_dn: String = result.dn.to_uppercase();
        let result_attrs: HashMap<String, Vec<String>> = result.attrs;
        let result_bin: HashMap<String, Vec<Vec<u8>>> = result.bin_attrs;

        // Debug for current object
        debug!("Parse computer: {result_dn}");

        // Trace all result attributes
        for (key, value) in &result_attrs {
            trace!("  {key:?}:{value:?}");
        }
        // Trace all bin result attributes
        for (key, value) in &result_bin {
            trace!("  {key:?}:{value:?}");
        }

        // Change all values...
        self.properties.domain = domain.to_uppercase();
        self.properties.distinguishedname = result_dn;
        self.properties.enabled = true;
        self.domain_sid = domain_sid.to_string();

        let mut sid: String = "".to_owned();
        let mut group_id: String = "".to_owned();
        // With a check
        for (key, value) in &result_attrs {
            match key.as_str() {
                "name" => {
                    let name = &value[0];
                    let email = format!("{}.{}",name.to_owned(),domain);
                    self.properties.name = email.to_uppercase();
                }
                "sAMAccountName" => {
                    self.properties.samaccountname = value[0].to_owned();
                }
                "dNSHostName" => {
                    self.properties.name = value[0].to_uppercase();
                }
                "description" => {
                    self.properties.description = Some(value[0].to_owned());
                }
                "operatingSystem" => {
                    self.properties.operatingsystem = value[0].to_owned();
                }
                //"operatingSystemServicePack" => {
                //    //operatingsystem
                //    let mut operating_system_servicepack = "".to_owned();
                //    //if result_attrs["operatingSystem"].len() > 0 {
                //    //    operating_system_servicepack.push_str(&result_attrs["operatingSystem"][0]);
                //    //}
                //    //operating_system_servicepack.push_str(&" ");
                //   operating_system_servicepack.push_str(&result_attrs["operatingSystemServicePack"][0]);
                //    computer_json["Properties"]["operatingsystem"] = operating_system_servicepack.to_owned();
                //}
                // "member" => {
                //     for member in value {
                //         localadmin_json["MemberId"] = member.to_owned();
                //         vec_localadmins.push(localadmin_json.to_owned());
                //     }
                //     computer_json["Members"] = vec_localadmins.to_owned();
                // }
                "lastLogon" => {
                    let lastlogon = &value[0].parse::<i64>().unwrap_or(0);
                    if lastlogon.is_positive() {
                        let epoch = convert_timestamp(*lastlogon);
                        self.properties.lastlogon = epoch;
                    }
                }
                "lastLogonTimestamp" => {
                    let lastlogontimestamp = &value[0].parse::<i64>().unwrap_or(0);
                    if lastlogontimestamp.is_positive() {
                        let epoch = convert_timestamp(*lastlogontimestamp);
                        self.properties.lastlogontimestamp = epoch;
                    }
                }
                "pwdLastSet" => {
                    let pwdlastset = &value[0].parse::<i64>().unwrap_or(0);
                    if pwdlastset.is_positive() {
                        let epoch = convert_timestamp(*pwdlastset);
                        self.properties.pwdlastset = epoch;
                    }
                }
                "whenCreated" => {
                    let epoch = string_to_epoch(&value[0])?;
                    if epoch.is_positive() {
                        self.properties.whencreated = epoch;
                    }
                }
                "servicePrincipalName" => {
                    //servicePrincipalName and hasspn
                    let mut result: Vec<String> = Vec::new();
                    for value in &result_attrs["servicePrincipalName"] {
                        result.push(value.to_owned());
                    }
                    self.properties.serviceprincipalnames = result;
                }
                "userAccountControl" => {
                    //userAccountControl
                    let uac = &value[0].parse::<u32>().unwrap();
                    let uac_flags = get_flag(*uac);
                    //trace!("UAC : {:?}",uac_flags);
                    for flag in uac_flags {
                        if flag.contains("AccountDisable") {
                            self.properties.enabled = false;
                        };
                        //if flag.contains("Lockout") { let enabled = true; computer_json["Properties"]["enabled"] = enabled; };
                        // KUD (Kerberos Unconstrained Delegation)
                        if flag.contains("TrustedForDelegation") {
                            self.properties.unconstraineddelegation = true;
                            self.unconstrained_delegation = true;
                        };
                        if flag.contains("TrustedToAuthForDelegation") {
                            self.properties.trustedtoauth = true;
                        };
                        if flag.contains("PasswordNotRequired") {
                            self.properties.passwordnotreqd = true;
                        };
                         if flag.contains("DontExpirePassword") {
                            self.properties.pwdneverexpires = true;
                        };
                        if flag.contains("ServerTrustAccount") {
                            self.properties.is_dc = true;
                            self.is_dc = true;
                        }
                    }
                }
                "msDS-AllowedToDelegateTo"  => {
                    // KCD (Kerberos Constrained Delegation)
                    //trace!(" AllowToDelegateTo: {:?}",&value);
                    // AllowedToDelegate
                    let mut vec_members2: Vec<Member> = Vec::new();
                    for objet in value {
                        let mut member_allowed_to_delegate = Member::new();
                        let split = objet.split("/");
                        let fqdn = split.collect::<Vec<&str>>()[1];
                        let mut checker = false;
                        for member in &vec_members2 {
                            if member.object_identifier().contains(fqdn.to_uppercase().as_str()) {
                                checker = true;
                            }
                        }
                        if !checker {
                            *member_allowed_to_delegate.object_identifier_mut() = fqdn.to_uppercase().to_owned().to_uppercase();
                            *member_allowed_to_delegate.object_type_mut() = "Computer".to_owned();
                            vec_members2.push(member_allowed_to_delegate.to_owned()); 
                        }
                    }
                    // *properties.allowedtodelegate = vec_members2.to_owned();
                    self.allowed_to_delegate = vec_members2;
                }
                // LAPS Legacy
                "ms-Mcs-AdmPwd" => {
                    // Laps is set, random password for local adminsitrator
                    // https://github.com/BloodHoundAD/SharpHound3/blob/7615860d963ba70751e1e5a00e02bb3fbca154c6/SharpHound3/Tasks/ACLTasks.cs#L313
                    info!(
                        "Your user can read LAPS password on {}: {}",
                        &result_attrs["name"][0].yellow().bold(),
                        &result_attrs["ms-Mcs-AdmPwd"][0].yellow().bold()
                    );
                    self.properties.haslaps = true;
                }
                "ms-Mcs-AdmPwdExpirationTime" => {
                    // LAPS is set, random password for local adminsitrator
                    // trace!("ms-Mcs-AdmPwdExpirationTime so haslaps=true");
                    self.properties.haslaps = true;
                }
                // New LAPS attributes
                "msLAPS-Password" => {
                    info!(
                        "Your user can read LAPS password on {}: {:?}",
                        &result_attrs["name"][0].yellow().bold(),
                        &value[0].yellow().bold()
                    );
                    self.properties.haslaps = true;
                }
                "msLAPS-EncryptedPassword" => {
                    info!(
                        "Your user can read uncrypted LAPS password on {} please check manually to decrypt it!",
                        &result_attrs["name"][0].yellow().bold()
                    );
                    self.properties.haslaps = true;
                }
                "msLAPS-PasswordExpirationTime" => {
                    // LAPS is set, random password for local adminsitrator
                    self.properties.haslaps = true;
                }
                "primaryGroupID" => {
                    group_id = value[0].to_owned();
                }
                "IsDeleted" => {
                    self.is_deleted = true;
                }
                "msDS-SupportedEncryptionTypes" => {
                    self.properties.supportedencryptiontypes = convert_encryption_types(value[0].parse::<i32>().unwrap_or(0));
                 }
                _ => {}
            }
        }

        // For all, bins attributs
        for (key, value) in &result_bin {
            match key.as_str() {
                "objectSid" => {
                    // objectSid raw to string
                    sid = sid_maker(LdapSid::parse(&value[0]).unwrap().1, domain);
                    self.object_identifier = sid.to_owned();

                    for domain_sid in OBJECT_SID_RE1.captures_iter(&sid) {
                        self.properties.domainsid = domain_sid[0].to_owned().to_string();
                    }
                }
                "nTSecurityDescriptor" => {
                    // nTSecurityDescriptor raw to string
                    // trace!("Parsing nTSecurityDescriptor..");
                    let relations_ace = parse_ntsecuritydescriptor(
                        self,
                        &value[0],
                        "Computer",
                        &result_attrs,
                        &result_bin,
                        domain,
                        schema_guid_map,
                    );
                    self.aces = relations_ace;
                }
                "msDS-AllowedToActOnBehalfOfOtherIdentity" => {
                    // RBCD (Resource-based constrained)
                    // msDS-AllowedToActOnBehalfOfOtherIdentity parsing ACEs
                    let relations_ace = parse_ntsecuritydescriptor(
                        self,
                        &value[0],
                        "Computer",
                        &result_attrs,
                        &result_bin,
                        domain,
                        schema_guid_map,
                    );
                    let mut vec_members_allowtoact: Vec<Member> = Vec::new();
                    let mut allowed_to_act = Member::new();
                    for delegated in relations_ace {
                        //trace!("msDS-AllowedToActOnBehalfOfOtherIdentity => ACE: {:?}",delegated);
                        // delegated["RightName"] == "Owner" => continue
                        if *delegated.right_name() == "GenericAll" {
                            *allowed_to_act.object_identifier_mut() = delegated.principal_sid().to_string();
                            vec_members_allowtoact.push(allowed_to_act.to_owned()); 
                            continue
                        }
                    }
                    self.allowed_to_act = vec_members_allowtoact;
                }
                _ => {}
            }
        }

        // primaryGroupID if group_id is set
        #[allow(irrefutable_let_patterns)]
        if let id = group_id {
            if let Some(part1) = SID_PART1_RE1.find(&sid) {
                self.primary_group_sid = format!("{}{}", part1.as_str(), id);
            } else {
                eprintln!("[!] Regex did not match any part of the SID");
            }
        }

        // Push DN and SID in HashMap
        dn_sid.insert(
            self.properties.distinguishedname.to_string(),
            self.object_identifier.to_string(),

        );
        // Push DN and Type
        sid_type.insert(
            self.object_identifier.to_string(),
            "Computer".to_string(),
        );

        fqdn_sid.insert(
            self.properties.name.to_string(),
            self.object_identifier.to_string(),
        );

        fqdn_ip.insert(
            self.properties.name.to_string(),
            String::from(""),
        );

        // Trace and return Computer struct
        // trace!("JSON OUTPUT: {:?}",serde_json::to_string(&self).unwrap());
        Ok(())
    }
}

impl LdapObject for Computer {
    // To JSON
    fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap()
    }

    // Get values
    fn get_object_identifier(&self) -> &String {
        &self.object_identifier
    }
    fn get_is_acl_protected(&self) -> &bool {
        &self.is_acl_protected
    }
    fn get_aces(&self) -> &Vec<AceTemplate> {
        &self.aces
    }
    fn get_spntargets(&self) -> &Vec<SPNTarget> {
        panic!("Not used by current object.");
    }
    fn get_allowed_to_delegate(&self) -> &Vec<Member> {
        &self.allowed_to_delegate
    }
    fn get_links(&self) -> &Vec<Link> {
        panic!("Not used by current object.");
    }
    fn get_contained_by(&self) -> &Option<Member> {
        &self.contained_by
    }
    fn get_child_objects(&self) -> &Vec<Member> {
        panic!("Not used by current object.");
    }
    fn get_haslaps(&self) -> &bool {
        &self.properties.haslaps
    }
    
    // Get mutable values
    fn get_aces_mut(&mut self) -> &mut Vec<AceTemplate> {
        &mut self.aces
    }
    fn get_spntargets_mut(&mut self) -> &mut Vec<SPNTarget> {
        panic!("Not used by current object.");
    }
    fn get_allowed_to_delegate_mut(&mut self) -> &mut Vec<Member> {
        &mut self.allowed_to_delegate
    }
  
    // Edit values
    fn set_is_acl_protected(&mut self, is_acl_protected: bool) {
        self.is_acl_protected = is_acl_protected;
        self.properties.isaclprotected = is_acl_protected;
    }
    fn set_aces(&mut self, aces: Vec<AceTemplate>) {
        self.aces = aces;
    }
    fn set_spntargets(&mut self, _spn_targets: Vec<SPNTarget>) {
        // Not used by current object.
    }
    fn set_allowed_to_delegate(&mut self, allowed_to_delegate: Vec<Member>) {
        self.allowed_to_delegate = allowed_to_delegate;
    }
    fn set_links(&mut self, _links: Vec<Link>) {
        // Not used by current object.
    }
    fn set_contained_by(&mut self, contained_by: Option<Member>) {
        self.contained_by = contained_by;
    }
    fn set_child_objects(&mut self, _child_objects: Vec<Member>) {
        // Not used by current object.
    }
}

// Computer properties structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ComputerProperties {
    domain: String,
    name: String,
    distinguishedname: String,
    domainsid: String,
    isaclprotected: bool,
    highvalue: bool,
    samaccountname: String,
    haslaps: bool,
    description: Option<String>,
    whencreated: i64,
    enabled: bool,
    unconstraineddelegation: bool,
    trustedtoauth: bool,  
    lastlogon: i64,
    lastlogontimestamp: i64,
    pwdlastset: i64,
    passwordnotreqd: bool,
    pwdneverexpires: bool,
    serviceprincipalnames: Vec<String>,
    operatingsystem: String,
    sidhistory: Vec<String>,
    supportedencryptiontypes: Vec<String>,
    #[serde(skip_serializing)]
    is_dc: bool
}

impl ComputerProperties {  
    // Immutable access.
    pub fn name(&self) -> &String {
        &self.name
    }
    pub fn unconstraineddelegation(&self) -> &bool {
        &self.unconstraineddelegation
    }
    pub fn enabled(&self) -> &bool {
        &self.enabled
    }
    pub fn get_is_dc(&self) -> &bool {
        &self.is_dc
    }
}