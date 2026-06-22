use serde_json::value::Value;
use serde::{Deserialize, Serialize};
use ldap3::SearchEntry;
use log::{debug, trace};
use std::collections::HashMap;
use std::error::Error;

use crate::enums::{decode_guid_le, parse_ntsecuritydescriptor};
use crate::utils::date::string_to_epoch;
use crate::objects::common::{LdapObject, AceTemplate, SPNTarget, Link, Member};

/// IssuancePolicie structure
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct IssuancePolicie {
    #[serde(rename = "Properties")]
    properties: IssuancePolicieProperties,
    #[serde(rename = "GroupLink")]
    group_link: GroupLink,
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

impl IssuancePolicie {
    // New IssuancePolicie
    pub fn new() -> Self { 
        Self {
            ..Default::default() 
        } 
    }

    /// Function to parse and replace value in json template for IssuancePolicie object.
    pub fn parse(
         &mut self,
        result: SearchEntry,
        domain: &str,
        dn_sid: &mut HashMap<String, String>,
        sid_type: &mut HashMap<String, String>,
        domain_sid: &str,
        schema_guid_map: &HashMap<String, String>,
    ) -> Result<(), Box<dyn Error>> {
        let result_dn: String = result.dn.to_uppercase();
        let result_attrs: HashMap<String, Vec<String>> = result.attrs;
        let result_bin: HashMap<String, Vec<Vec<u8>>> = result.bin_attrs;

        // Debug for current object
        debug!("Parse IssuancePolicie: {result_dn}");

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
                "description" => {
                    self.properties.description = Some(value[0].to_owned());
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
                "displayName" => {
                    self.properties.name = format!("{}@{}",&value[0],domain).to_uppercase();
                    self.properties.displayname = value[0].to_owned();
                }
                "msPKI-Cert-Template-OID" => {
                    self.properties.certtemplateoid = value[0].to_owned();
                }
                _ => {}
            }
        }

        // For all, bins attributs
        for (key, value) in &result_bin {
            match key.as_str() {
                "objectGUID" => {
                    // objectGUID raw to string
                    let guid = decode_guid_le(&value[0]);
                    self.object_identifier = guid.to_owned();
                }
                "nTSecurityDescriptor" => {
                    // nTSecurityDescriptor raw to string
                    let relations_ace = parse_ntsecuritydescriptor(
                        self,
                         &value[0],
                        "IssuancePolicie",
                         &result_attrs,
                         &result_bin,
                         domain,
                         schema_guid_map,
                    );
                    self.aces = relations_ace;
                }
                _ => {}
            }
        }

        // Push DN and SID in HashMap
        if self.object_identifier != "SID" {
            dn_sid.insert(
                self.properties.distinguishedname.to_owned(),
                self.object_identifier.to_owned()
            );
            // Push DN and Type
            sid_type.insert(
                self.object_identifier.to_owned(),
                "IssuancePolicie".to_string()
            );
        }

        // Trace and return IssuancePolicie struct
        // trace!("JSON OUTPUT: {:?}",serde_json::to_string(&self).unwrap());
        Ok(())
    }
}

impl LdapObject for IssuancePolicie {
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


// IssuancePolicie properties structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IssuancePolicieProperties {
    domain: String,
    name: String,
    distinguishedname: String,
    domainsid: String,
    isaclprotected: bool,
    description: Option<String>,
    whencreated: i64,
    displayname: String,
    certtemplateoid: String,
}

impl Default for IssuancePolicieProperties {
    fn default() -> IssuancePolicieProperties {
        IssuancePolicieProperties {
            domain: String::from(""),
            name: String::from(""),
            distinguishedname: String::from(""),
            domainsid: String::from(""),
            isaclprotected: false,
            description: None,
            whencreated: -1,
            displayname: String::from(""),
            certtemplateoid: String::from(""),
        }
    }
}
/// GroupLink structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GroupLink {
    #[serde(rename = "ObjectIdentifier")]
    object_identifier: Option<String>,
    #[serde(rename = "ObjectType")]
    object_type: String,
}

impl GroupLink {
    // New object.
    pub fn new(object_identifier: Option<String>, object_type: String) -> Self { Self { object_identifier, object_type } }

    // Immutable access.
    pub fn object_identifier(&self) -> &Option<String> {
        &self.object_identifier
    }
    pub fn object_type(&self) -> &String {
        &self.object_type
    }
 
    // Mutable access.
    pub fn object_identifier_mut(&mut self) -> &mut Option<String> {
        &mut self.object_identifier
    }
    pub fn object_type_mut(&mut self) -> &mut String {
        &mut self.object_type
    }
}

// Implement Default trait for GroupLink
impl Default for GroupLink {
    fn default() -> Self {
        Self {
            object_identifier: None,
            object_type: "Base".to_string(),
        }
    }
}