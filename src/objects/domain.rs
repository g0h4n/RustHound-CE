use serde_json::value::Value;
use serde::{Deserialize, Serialize};
use colored::Colorize;
use ldap3::SearchEntry;
use log::{info, debug, trace};
use std::collections::HashMap;
use std::error::Error;

use crate::enums::regex::OBJECT_SID_RE1;
use crate::objects::common::{LdapObject, GPOChange, Link, AceTemplate, SPNTarget, Member};
use crate::objects::trust::Trust;
use crate::utils::date::{span_to_string, string_to_epoch};
use crate::enums::acl::parse_ntsecuritydescriptor;
use crate::enums::forestlevel::get_forest_level;
use crate::enums::gplink::parse_gplink;
use crate::enums::secdesc::LdapSid;
use crate::enums::sid::sid_maker;

/// Domain structure
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Domain {
    #[serde(rename = "Properties")]
    properties: DomainProperties,
    #[serde(rename = "GPOChanges")]
    gpo_changes: GPOChange,
    #[serde(rename = "ChildObjects")]
    child_objects: Vec<Member>,
    #[serde(rename = "Trusts")]
    trusts: Vec<Trust>,
    #[serde(rename = "Links")]
    links: Vec<Link>,
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
}

impl Domain {
    // New domain.
    pub fn new() -> Self { 
        Self { ..Default::default() } 
    }

    // Get access.
    pub fn object_identifier(&self) -> &String {
        &self.object_identifier
    }

    // Mutable access.
    pub fn properties_mut(&mut self) -> &mut DomainProperties {
        &mut self.properties
    }
    pub fn object_identifier_mut(&mut self) -> &mut String {
        &mut self.object_identifier
    }
    pub fn gpo_changes_mut(&mut self) -> &mut GPOChange {
        &mut self.gpo_changes
    }
    pub fn trusts_mut(&mut self) -> &mut Vec<Trust> {
        &mut self.trusts
    }

    /// Function to parse and replace value for domain object.
    /// <https://bloodhound.readthedocs.io/en/latest/further-reading/json.html#domains>
    pub fn parse(
        &mut self,
        result: SearchEntry,
        domain_name: &str,
        dn_sid: &mut HashMap<String, String>,
        sid_type: &mut HashMap<String, String>,
    ) -> Result<String, Box<dyn Error>> {
        let result_dn: String = result.dn.to_uppercase();
        let result_attrs: HashMap<String, Vec<String>> = result.attrs;
        let result_bin: HashMap<String, Vec<Vec<u8>>> = result.bin_attrs;

        // Debug for current object
        debug!("Parse domain: {result_dn}");

        // Trace all result attributes
        for (key, value) in &result_attrs {
            trace!("  {key:?}:{value:?}");
        }
        // Trace all bin result attributes
        for (key, value) in &result_bin {
            trace!("  {key:?}:{value:?}");
        }

        // Change all values...
        self.properties.domain = domain_name.to_uppercase();
        self.properties.distinguishedname = result_dn;

        // Change all values...
        #[allow(unused_assignments)]
        let mut sid: String = "".to_owned();
        let mut global_domain_sid: String = "DOMAIN_SID".to_owned();
        // With a check
        for (key, value) in &result_attrs {
            match key.as_str() {
                "distinguishedName" => {
                    // name & domain & distinguishedname
                    self.properties.distinguishedname = value[0].to_owned().to_uppercase();
                    let name = value[0]
                        .split(",")
                        .filter(|x| x.starts_with("DC="))
                        .map(|x| x.strip_prefix("DC=").unwrap_or(""))
                        .collect::<Vec<&str>>()
                        .join(".");
                    self.properties.name = name.to_uppercase();
                    self.properties.domain = name.to_uppercase();
                }
                "msDS-Behavior-Version" => {
                    let level = get_forest_level(value[0].to_string());
                    self.properties.functionallevel  = level;
                }
                "whenCreated" => {
                    let epoch = string_to_epoch(&value[0])?;
                    if epoch.is_positive() {
                        self.properties.whencreated = epoch;
                    }
                }
                "gPLink" => {
                    self.links = parse_gplink(value[0].to_string())?;
                }
                "isCriticalSystemObject" => {
                    self.properties.highvalue = value[0].contains("TRUE");
                }
                // The number of computer accounts that a user is allowed to create in a domain.
                "ms-DS-MachineAccountQuota" => {
                    let machine_account_quota = value[0].parse::<i32>().unwrap_or(0);
                    self.properties.machineaccountquota = machine_account_quota;
                    if machine_account_quota > 0 {
                        info!("MachineAccountQuota: {}", machine_account_quota.to_string().yellow().bold());
                    }
                }
                "IsDeleted" => {
                    self.is_deleted = true;
                }
                "msDS-ExpirePasswordsOnSmartCardOnlyAccounts" => {
                    self.properties.expirepasswordsonsmartcardonlyaccounts = true;
                }
                "minPwdLength" => {
                    self.properties.minpwdlength = value[0].parse::<i32>().unwrap_or(0);
                }
                "pwdProperties" => {
                    self.properties.pwdproperties = value[0].parse::<i32>().unwrap_or(0);
                }
                "pwdHistoryLength" => {
                    self.properties.pwdhistorylength = value[0].parse::<i32>().unwrap_or(0);
                }
                "lockoutThreshold" => {
                    self.properties.lockoutthreshold = value[0].parse::<i32>().unwrap_or(0);
                }
                "minPwdAge" => {
                    self.properties.minpwdage = span_to_string(value[0].parse::<i64>().unwrap_or(0));
                }
                "maxPwdAge" => {
                    self.properties.maxpwdage = span_to_string(value[0].parse::<i64>().unwrap_or(0));
                }
                "lockoutDuration" => {
                    self.properties.lockoutduration = span_to_string(value[0].parse::<i64>().unwrap_or(0));
                }
                "lockOutObservationWindow" => {
                    self.properties.lockoutobservationwindow = value[0].parse::<i64>().unwrap_or(0);
                }
                _ => {}
            }
        }

        // For all, bins attributes
        for (key, value) in &result_bin {
            match key.as_str() {
                "objectSid" => {
                    // objectSid raw to string
                    sid = sid_maker(LdapSid::parse(&value[0]).unwrap().1, domain_name);
                    self.object_identifier = sid.to_owned();

                    for domain_sid in OBJECT_SID_RE1.captures_iter(&sid) {
                        self.properties.domainsid = domain_sid[0].to_owned().to_string();
                        global_domain_sid = domain_sid[0].to_owned().to_string();
                    }

                    // Data Quality flag
                    self.properties.collected = true;
                }
                "nTSecurityDescriptor" => {
                    // nTSecurityDescriptor raw to string
                    let relations_ace = parse_ntsecuritydescriptor(
                        self,
                        &value[0],
                        "Domain",
                        &result_attrs,
                        &result_bin,
                        domain_name,
                    );
                    self.aces = relations_ace;
                }
                _ => {}
            }
        }

        // Push DN and SID in HashMap
        dn_sid.insert(
        self.properties.distinguishedname.to_string(),
        self.object_identifier.to_string()
        );
        // Push DN and Type
        sid_type.insert(
            self.object_identifier.to_string(),
            "Domain".to_string(),
        );

        // Trace and return Domain struct
        // trace!("JSON OUTPUT: {:?}",serde_json::to_string(&self).unwrap());
        Ok(global_domain_sid)
    }
}

impl LdapObject for Domain {
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
        panic!("Not used by current object.");
    }
    fn get_links(&self) -> &Vec<Link> {
        &self.links
    }
    fn get_contained_by(&self) -> &Option<Member> {
        &self.contained_by
    }
    fn get_child_objects(&self) -> &Vec<Member> {
        &self.child_objects
    }
    fn get_haslaps(&self) -> &bool {
        &false
    }
    
    // Get mutable values
    fn get_aces_mut(&mut self) -> &mut Vec<AceTemplate> {
        &mut self.aces
    }
    fn get_spntargets_mut(&mut self) -> &mut Vec<SPNTarget> {
        panic!("Not used by current object.");
    }
    fn get_allowed_to_delegate_mut(&mut self) -> &mut Vec<Member> {
        panic!("Not used by current object.");
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
    fn set_allowed_to_delegate(&mut self, _allowed_to_delegate: Vec<Member>) {
        // Not used by current object.
    }
    fn set_links(&mut self, links: Vec<Link>) {
        self.links = links;
    }
    fn set_contained_by(&mut self, contained_by: Option<Member>) {
        self.contained_by = contained_by;
    }
    fn set_child_objects(&mut self, child_objects: Vec<Member>) {
        self.child_objects = child_objects
    }
}

// Domain properties structure
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct DomainProperties {
    domain: String,
    name: String,
    distinguishedname: String,
    domainsid: String,
    isaclprotected: bool,
    highvalue: bool,
    description: Option<String>,
    whencreated: i64,
    machineaccountquota: i32,
    expirepasswordsonsmartcardonlyaccounts: bool,
    minpwdlength: i32,
    pwdproperties: i32,
    pwdhistorylength: i32,
    lockoutthreshold: i32,
    minpwdage: String,
    maxpwdage: String,
    lockoutduration: String,
    lockoutobservationwindow: i64,
    functionallevel: String,
    collected: bool
}

impl DomainProperties {
    // Mutable access.
    pub fn domain_mut(&mut self) -> &mut String {
       &mut self.domain
    }
    pub fn name_mut(&mut self) -> &mut String {
       &mut self.name
    }
    pub fn highvalue_mut(&mut self) -> &mut bool {
        &mut self.highvalue
     }
    pub fn distinguishedname_mut(&mut self) -> &mut String {
        &mut self.distinguishedname
     }
} 