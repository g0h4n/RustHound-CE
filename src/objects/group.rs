use serde::{Deserialize, Serialize};
use serde_json::value::Value;
use ldap3::SearchEntry;
use log::{debug, trace};
use std::collections::HashMap;
use std::error::Error;

use crate::enums::regex::OBJECT_SID_RE1;
use crate::objects::common::{LdapObject, AceTemplate, SPNTarget, Link, Member};
use crate::enums::acl::parse_ntsecuritydescriptor;
use crate::enums::secdesc::LdapSid;
use crate::enums::sid::{objectsid_to_vec8, sid_maker};
use crate::utils::date::string_to_epoch;

/// Group structure
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Group {
    #[serde(rename = "ObjectIdentifier")]
    object_identifier: String,
    #[serde(rename = "IsDeleted")]
    is_deleted: bool,
    #[serde(rename = "IsACLProtected")]
    is_acl_protected: bool,
    #[serde(rename = "Properties")]
    properties: GroupProperties,
    #[serde(rename = "Members")]
    members: Vec<Member>,
    #[serde(rename = "Aces")]
    aces: Vec<AceTemplate>,
    #[serde(rename = "ContainedBy")]
    contained_by: Option<Member>,
}

impl Group {
    // New group.
    pub fn new() -> Self { 
        Self { ..Default::default() } 
    }

    // Immutable access.
    pub fn members(&self) -> &Vec<Member> {
        &self.members
    }

    // Mutable access.
    pub fn properties_mut(&mut self) -> &mut GroupProperties {
        &mut self.properties
    }
    pub fn object_identifier_mut(&mut self) -> &mut String {
        &mut self.object_identifier
    }
    pub fn members_mut(&mut self) -> &mut Vec<Member> {
        &mut self.members
    }

    /// Function to parse and replace value for group object.
    /// <https://bloodhound.readthedocs.io/en/latest/further-reading/json.html#groups>
    pub fn parse(
        &mut self,
        result: SearchEntry,
        domain: &str,
        dn_sid: &mut HashMap<String, String>,
        sid_type: &mut HashMap<String, String>,
        domain_sid: &str,
    ) -> Result<(), Box<dyn Error>> {
        let result_dn: String = result.dn.to_uppercase();
        let result_attrs: HashMap<String, Vec<String>> = result.attrs;
        let result_bin: HashMap<String, Vec<Vec<u8>>> = result.bin_attrs;

        debug!("Parse group: {result_dn}");

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
        self.properties.domainsid = domain_sid.to_string();

        // With a check
        for (key, value) in &result_attrs {
            match key.as_str() {
                "name" => {
                    let name = &value[0];
                    let email = format!("{}@{}", name.to_owned(), domain);
                    self.properties.name = email.to_uppercase();
                }
                "description" => {
                    self.properties.description = Some(value[0].to_owned());
                }
                "adminCount" => {
                    let isadmin = &value[0];
                    let mut admincount = false;
                    if isadmin == "1" {
                        admincount = true;
                    }
                    self.properties.admincount = admincount;
                }
                "sAMAccountName" => {
                    self.properties.samaccountname = value[0].to_owned();
                }
                "member" => {
                    if !value.is_empty() {
                        let mut _vec_members: Vec<Member> = Vec::new();

                        for member in value {
                            let _member = member.trim();
                            if _member.is_empty() {
                                continue;
                            }
                            if _member.eq_ignore_ascii_case("SID") {
                                continue;
                            }

                            let mut m = Member::new();
                            *m.object_identifier_mut() = _member.to_uppercase();
                            _vec_members.push(m);
                        }
                        
                        self.members = _vec_members;
                    }
                }
                "objectSid" => {
                    // objectSid to vec and raw to string
                    let vec_sid = objectsid_to_vec8(&value[0]);
                    let sid = sid_maker(LdapSid::parse(&vec_sid).unwrap().1, domain);
                    self.object_identifier = sid.to_owned();

                    /*let re = Regex::new(r"^S-[0-9]{1}-[0-9]{1}-[0-9]{1,}-[0-9]{1,}-[0-9]{1,}-[0-9]{1,}").unwrap();
                    for domain_sid in re.captures_iter(&sid) 
                    {
                        group_json["Properties"]["domainsid"] = domain_sid[0].to_owned().to_string();
                    }*/

                    // highvalue
                    if sid.ends_with("-512") 
                        || sid.ends_with("-516") 
                        || sid.ends_with("-519") 
                        || sid.ends_with("-520") 
                    {
                        self.properties.highvalue = true;
                    } else if sid.ends_with("S-1-5-32-544") 
                        || sid.ends_with("S-1-5-32-548") 
                        || sid.ends_with("S-1-5-32-549")
                        || sid.ends_with("S-1-5-32-550") 
                        || sid.ends_with("S-1-5-32-551")
                    {
                        self.properties.highvalue = true;
                    } else {
                        self.properties.highvalue = false;
                    }
                }
                "whenCreated" => {
                    let epoch = string_to_epoch(&value[0])?;
                    if epoch.is_positive() {
                        self.properties.whencreated = epoch;
                    }
                }
                "IsDeleted" => {
                    self.is_deleted = true;
                }
                _ => {}
            }
        }

        // For all, bins attributs
        for (key, value) in &result_bin {
            match key.as_str() {
                "objectSid" => {
                    // objectSid raw to string
                    let sid = sid_maker(LdapSid::parse(&value[0]).unwrap().1, domain);
                    self.object_identifier = sid.to_owned();

                    for domain_sid in OBJECT_SID_RE1.captures_iter(&sid) {
                        self.properties.domainsid = domain_sid[0].to_owned().to_string();
                    }
    
                    // highvalue
                    if sid.ends_with("-512") 
                        || sid.ends_with("-516") 
                        || sid.ends_with("-519") 
                        || sid.ends_with("-520") 
                    {
                        self.properties.highvalue = true;
                    }
                    else if sid.ends_with("S-1-5-32-544") 
                        || sid.ends_with("S-1-5-32-548") 
                        || sid.ends_with("S-1-5-32-549")
                        || sid.ends_with("S-1-5-32-550") 
                        || sid.ends_with("S-1-5-32-551") 
                    {
                        self.properties.highvalue = true;
                    }
                    else {
                        self.properties.highvalue = false;
                    }
                }
                "nTSecurityDescriptor" => {
                    // nTSecurityDescriptor raw to string
                    let relations_ace = parse_ntsecuritydescriptor(
                        self,
                        &value[0],
                        "Group",
                        &result_attrs,
                        &result_bin,
                        domain,
                    );
                    self.aces = relations_ace;
                }
                _ => {}
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
            "Group".to_string(),
        );

        // Trace and return Group struct
        // trace!("JSON OUTPUT: {:?}",serde_json::to_string(&self).unwrap());
        Ok(())
    }
}

impl LdapObject for Group {
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
        panic!("Not used by current object.");
    }
    fn get_contained_by(&self) -> &Option<Member> {
        &self.contained_by
    }
    fn get_child_objects(&self) -> &Vec<Member> {
        panic!("Not used by current object.");
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

// Group properties structure
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct GroupProperties {
    domain: String,
    name: String,
    distinguishedname: String,
    domainsid: String,
    isaclprotected: bool,
    highvalue: bool,
    samaccountname: String,
    description: Option<String>,
    whencreated: i64,
    admincount: bool,
}

impl GroupProperties {
    // Mutable access.
    pub fn name_mut(&mut self) -> &mut String {
        &mut self.name
    }
    pub fn domain_mut(&mut self) -> &mut String {
        &mut self.domain
    }
    pub fn domainsid_mut(&mut self) -> &mut String {
        &mut self.domainsid
    }
    pub fn highvalue_mut(&mut self) -> &mut bool {
        &mut self.highvalue
    }
}