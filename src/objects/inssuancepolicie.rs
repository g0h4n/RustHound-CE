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
    /// `msDS-OIDToGroupLink` (upper case), resolved by the checker.
    #[serde(skip)]
    group_link_dn: Option<String>,
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
                "isDeleted" => {
                    self.is_deleted = true;
                }
                "displayName" => {
                    self.properties.name = format!("{}@{}",&value[0],domain).to_uppercase();
                    self.properties.displayname = value[0].to_owned();
                }
                "msPKI-Cert-Template-OID" => {
                    self.properties.certtemplateoid = value[0].to_owned();
                }
                "msDS-OIDToGroupLink" => {
                    self.group_link_dn = value.first().map(|dn| dn.to_uppercase());
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
                    self.properties.objectguid = guid;
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

    /// Resolve the group linked by `msDS-OIDToGroupLink` (ESC13) once all
    /// objects are parsed. A group missing from the collected data, such as
    /// one from another domain, leaves `GroupLink` and `oidgrouplink` unset.
    pub fn resolve_group_link(
        &mut self,
        dn_sid: &HashMap<String, String>,
        sid_type: &HashMap<String, String>,
    ) {
        let Some(sid) = self.group_link_dn.as_ref().and_then(|dn| dn_sid.get(dn)) else {
            return;
        };
        let object_type = sid_type.get(sid).cloned().unwrap_or_else(|| "Base".to_string());
        self.properties.oidgrouplink = Some(sid.to_owned());
        self.group_link = GroupLink::new(Some(sid.to_owned()), object_type);
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
    fn set_owner_rights_flags(&mut self, any: bool, any_inherited: bool) {
        self.properties.doesanyacegrantownerrights = any;
        self.properties.doesanyinheritedacegrantownerrights = any_inherited;
    }
}


// IssuancePolicie properties structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IssuancePolicieProperties {
    domain: String,
    name: String,
    distinguishedname: String,
    domainsid: String,
    objectguid: String,
    doesanyacegrantownerrights: bool,
    doesanyinheritedacegrantownerrights: bool,
    isaclprotected: bool,
    description: Option<String>,
    whencreated: i64,
    displayname: String,
    certtemplateoid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    oidgrouplink: Option<String>,
}

impl Default for IssuancePolicieProperties {
    fn default() -> IssuancePolicieProperties {
        IssuancePolicieProperties {
            domain: String::from(""),
            name: String::from(""),
            distinguishedname: String::from(""),
            domainsid: String::from(""),
            objectguid: String::from(""),
            doesanyacegrantownerrights: false,
            doesanyinheritedacegrantownerrights: false,
            isaclprotected: false,
            description: None,
            whencreated: -1,
            displayname: String::from(""),
            certtemplateoid: String::from(""),
            oidgrouplink: None,
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

#[cfg(test)]
mod tests {
    use super::*;

    const GROUP_DN: &str = "CN=PKI Admins,CN=Users,DC=example,DC=local";
    const GROUP_SID: &str = "S-1-5-21-1-2-3-1104";

    fn parse_issuancepolicie(group_link: Option<&str>) -> IssuancePolicie {
        let mut attrs = HashMap::new();
        attrs.insert("displayName".to_string(), vec!["LabPolicy".to_string()]);
        attrs.insert(
            "msPKI-Cert-Template-OID".to_string(),
            vec!["1.3.6.1.4.1.311.21.8.1.2".to_string()],
        );
        if let Some(dn) = group_link {
            attrs.insert("msDS-OIDToGroupLink".to_string(), vec![dn.to_string()]);
        }
        let result = SearchEntry {
            dn: "CN=1.2ABCDEF,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=local".to_string(),
            attrs,
            bin_attrs: HashMap::new(),
        };
        let mut issuancepolicie = IssuancePolicie::new();
        issuancepolicie
            .parse(
                result,
                "example.local",
                &mut HashMap::new(),
                &mut HashMap::new(),
                "S-1-5-21-1-2-3",
                &HashMap::new(),
            )
            .unwrap();
        issuancepolicie
    }

    fn collected_group() -> (HashMap<String, String>, HashMap<String, String>) {
        let dn_sid = HashMap::from([(GROUP_DN.to_uppercase(), GROUP_SID.to_string())]);
        let sid_type = HashMap::from([(GROUP_SID.to_string(), "Group".to_string())]);
        (dn_sid, sid_type)
    }

    #[test]
    fn resolve_group_link_sets_the_linked_group_sid() {
        let mut issuancepolicie = parse_issuancepolicie(Some(GROUP_DN));
        let (dn_sid, sid_type) = collected_group();
        issuancepolicie.resolve_group_link(&dn_sid, &sid_type);
        let json = issuancepolicie.to_json();

        assert_eq!(json["Properties"]["oidgrouplink"], GROUP_SID);
        assert_eq!(
            json["GroupLink"],
            serde_json::json!({"ObjectIdentifier": GROUP_SID, "ObjectType": "Group"})
        );
    }

    #[test]
    fn unresolved_group_link_keeps_the_defaults() {
        let (dn_sid, sid_type) = collected_group();
        for group_link in [None, Some("CN=Other,CN=Users,DC=other,DC=local")] {
            let mut issuancepolicie = parse_issuancepolicie(group_link);
            issuancepolicie.resolve_group_link(&dn_sid, &sid_type);
            let json = issuancepolicie.to_json();

            assert!(json["Properties"].get("oidgrouplink").is_none(), "{group_link:?}");
            assert_eq!(
                json["GroupLink"],
                serde_json::json!({"ObjectIdentifier": null, "ObjectType": "Base"}),
                "{group_link:?}"
            );
        }
    }
}
