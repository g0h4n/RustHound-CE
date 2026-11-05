use ldap3::SearchEntry;
use log::{debug, trace};
use serde::{Deserialize, Serialize};
use serde_json::value::Value;
use std::collections::HashMap;
use std::error::Error;

use crate::enums::acl::parse_ntsecuritydescriptor;
use crate::enums::decode_guid_le;
use crate::objects::common::{AceTemplate, LdapObject, Link, Member, SPNTarget};
use crate::utils::date::string_to_epoch;

/// Site structure
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Site {
    #[serde(rename = "Properties")]
    properties: SiteProperties,
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
    #[serde(rename = "ChildObjects")]
    child_objects: Vec<Member>,
    #[serde(rename = "Links")]
    links: Vec<Link>,
    #[serde(rename = "InheritanceHashes")]
    inheritance_hashes: Vec<String>,
}

impl Site {
    // New site.
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    /// Function to parse and replace value for Site object.
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
        debug!("Parse site: {result_dn}");

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

        // Check and replace value
        for (key, value) in &result_attrs {
            match key.as_str() {
                "objectClass" => {
                    self.properties.objectclass = value.clone();
                }
                "whenCreated" => {
                    if let Some(v) = value.first() {
                        let epoch = string_to_epoch(v)?;
                        if epoch.is_positive() {
                            self.properties.whencreated = epoch;
                        }
                    }
                }
                "isDeleted" => {
                    self.is_deleted = true;
                }
                "cn" => {
                    if let Some(v) = value.first() {
                        self.properties.name = format!("{}@{}", v, domain).to_uppercase();
                    }
                }
                _ => {}
            }
        }

        // For all, bins attributes
        if let Some(guid_bytes) = result_bin.get("objectGUID").and_then(|v| v.first()) {
            // objectGUID raw to string
            let guid = decode_guid_le(guid_bytes);
            self.object_identifier = guid.clone();
            self.properties.objectguid = guid;
        }
        if let Some(sd) = result_bin.get("nTSecurityDescriptor").and_then(|v| v.first()) {
            // nTSecurityDescriptor raw to string
            self.aces = parse_ntsecuritydescriptor(
                self,
                sd,
                "Site",
                &result_attrs,
                &result_bin,
                domain,
                schema_guid_map,
            );
        }

        // Push DN and SID in HashMap
        dn_sid.insert(
            self.properties.distinguishedname.to_string(),
            self.object_identifier.to_string(),
        );
        // Push DN and Type
        sid_type.insert(self.object_identifier.to_string(), "Site".to_string());

        // Trace and return Site struct
        // trace!("JSON OUTPUT: {:?}",serde_json::to_string(&self).unwrap());
        Ok(())
    }
}

impl LdapObject for Site {
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
        panic!("Not used by current object.")
    }
    fn get_allowed_to_delegate(&self) -> &Vec<Member> {
        panic!("Not used by current object.")
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
        panic!("Not used by current object.")
    }
    fn get_allowed_to_delegate_mut(&mut self) -> &mut Vec<Member> {
        panic!("Not used by current object.")
    }
    // Edit values
    fn set_is_acl_protected(&mut self, value: bool) {
        self.is_acl_protected = value;
        self.properties.isaclprotected = value;
    }
    fn set_aces(&mut self, value: Vec<AceTemplate>) {
        self.aces = value;
    }
    fn set_spntargets(&mut self, _spn_targets: Vec<SPNTarget>) {
        // Not used by current object.
    }
    fn set_allowed_to_delegate(&mut self, _allowed_to_delegate: Vec<Member>) {
        // Not used by current object.
    }
    fn set_links(&mut self, value: Vec<Link>) {
        self.links = value;
    }
    fn set_contained_by(&mut self, value: Option<Member>) {
        self.contained_by = value;
    }
    fn set_child_objects(&mut self, value: Vec<Member>) {
        self.child_objects = value;
    }
    fn set_owner_rights_flags(&mut self, any: bool, inherited: bool) {
        self.properties.doesanyacegrantownerrights = any;
        self.properties.doesanyinheritedacegrantownerrights = inherited;
    }
}

// Site properties structure
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct SiteProperties {
    domain: String,
    name: String,
    distinguishedname: String,
    domainsid: String,
    objectguid: String,
    doesanyacegrantownerrights: bool,
    doesanyinheritedacegrantownerrights: bool,
    isaclprotected: bool,
    whencreated: i64,
    objectclass: Vec<String>,
}
