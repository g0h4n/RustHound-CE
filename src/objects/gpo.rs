use ldap3::SearchEntry;
use log::{debug, trace, warn};
use serde::{Deserialize, Serialize};
use serde_json::value::Value;
use std::collections::HashMap;
use std::error::Error;

use crate::enums::acl::parse_ntsecuritydescriptor;
use crate::enums::decode_guid_le;
use crate::objects::common::{AceTemplate, LdapObject, Link, Member, SPNTarget};
use crate::utils::date::string_to_epoch;

/// Gpo structure
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Gpo {
    #[serde(rename = "Properties")]
    properties: GpoProperties,
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
    #[serde(rename = "Links")]
    links: Vec<Link>,
}

impl Gpo {
    // New gpo.
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    /// Whether the GPO's computer configuration is applicable.
    pub fn computer_configuration_enabled(&self) -> bool {
        if self.properties.gpostatus.is_empty() {
            warn!(
                "GPO {} has no flags value; treating computer configuration as enabled for SharpHound compatibility",
                self.properties.distinguishedname
            );
            return true;
        }

        match self.properties.gpostatus.parse::<u32>() {
            Ok(flags) => flags & 0x2 == 0,
            Err(_) => {
                warn!(
                    "GPO {} has invalid flags value {:?}; skipping computer configuration",
                    self.properties.distinguishedname, self.properties.gpostatus
                );
                false
            }
        }
    }

    pub(crate) fn sysvol_guid(&self) -> Option<String> {
        self.properties
            .gpcpath
            .rsplit(['\\', '/'])
            .find(|part| !part.is_empty())
            .map(str::to_uppercase)
    }

    /// Function to parse and replace value for GPO object.
    /// <https://bloodhound.readthedocs.io/en/latest/further-reading/json.html#gpos>
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
        debug!("Parse gpo: {result_dn}");

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
                "displayName" => {
                    let name = &value[0];
                    let email = format!("{}@{}", name.to_owned(), domain);
                    self.properties.name = email.to_uppercase();
                }
                "description" => {
                    self.properties.description = value.first().cloned();
                }
                "whenCreated" => {
                    let epoch = string_to_epoch(&value[0])?;
                    if epoch.is_positive() {
                        self.properties.whencreated = epoch;
                    }
                }
                "gPCFileSysPath" => {
                    self.properties.gpcpath = value[0].to_owned();
                }
                "flags" => {
                    self.properties.gpostatus = value.first().cloned().unwrap_or_default();
                }
                "isDeleted" => {
                    self.is_deleted = true;
                }
                _ => {}
            }
        }

        // For all, bins attributes
        for (key, value) in &result_bin {
            match key.as_str() {
                "objectGUID" => {
                    // objectGUID raw to string
                    self.object_identifier = decode_guid_le(&value[0]).to_owned();
                }
                "nTSecurityDescriptor" => {
                    // nTSecurityDescriptor raw to string
                    let relations_ace = parse_ntsecuritydescriptor(
                        self,
                        &value[0],
                        "Gpo",
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
        dn_sid.insert(
            self.properties.distinguishedname.to_string(),
            self.object_identifier.to_string(),
        );
        // Push DN and Type
        sid_type.insert(self.object_identifier.to_string(), "Gpo".to_string());

        // Trace and return Gpo struct
        // trace!("JSON OUTPUT: {:?}",serde_json::to_string(&self).unwrap());
        Ok(())
    }
}

impl LdapObject for Gpo {
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
    fn set_links(&mut self, links: Vec<Link>) {
        self.links = links;
    }
    fn set_contained_by(&mut self, contained_by: Option<Member>) {
        self.contained_by = contained_by;
    }
    fn set_child_objects(&mut self, _child_objects: Vec<Member>) {
        // Not used by current object.
    }
}

// Gpo properties structure
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct GpoProperties {
    domain: String,
    name: String,
    distinguishedname: String,
    domainsid: String,
    isaclprotected: bool,
    highvalue: bool,
    description: Option<String>,
    whencreated: i64,
    gpcpath: String,
    gpostatus: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_gpo_with_flags(flags: Option<&str>) -> Gpo {
        let mut attrs = HashMap::from([
            ("displayName".to_string(), vec!["Test GPO".to_string()]),
            (
                "gPCFileSysPath".to_string(),
                vec![r"\\example.local\SYSVOL\example.local\Policies\{00000000-0000-0000-0000-000000000000}".to_string()],
            ),
        ]);
        if let Some(flags) = flags {
            attrs.insert("flags".to_string(), vec![flags.to_string()]);
        }
        let result = SearchEntry {
            dn: "CN={00000000-0000-0000-0000-000000000000},CN=Policies,CN=System,DC=example,DC=local".to_string(),
            attrs,
            bin_attrs: HashMap::new(),
        };
        let mut gpo = Gpo::new();
        let mut dn_sid = HashMap::new();
        let mut sid_type = HashMap::new();

        gpo.parse(
            result,
            "example.local",
            &mut dn_sid,
            &mut sid_type,
            "S-1-5-21-111111111-222222222-333333333",
            &HashMap::new(),
        )
        .unwrap();

        gpo
    }

    #[test]
    fn parse_preserves_gpo_status_for_all_defined_flag_values() {
        for flags in ["0", "1", "2", "3"] {
            let gpo = parse_gpo_with_flags(Some(flags));
            assert_eq!(
                gpo.to_json()["Properties"]["gpostatus"],
                flags,
                "flags={flags} should be retained as gpostatus",
            );
        }
    }

    #[test]
    fn computer_configuration_applicability_follows_flags_bit_one() {
        let cases = [
            (Some("0"), true),
            (Some("1"), true),
            (Some("2"), false),
            (Some("3"), false),
            (Some("4"), true),
            (Some("6"), false),
            (None, true),
            (Some(""), true),
            (Some("not-a-number"), false),
            (Some("4294967296"), false),
        ];

        for (flags, expected) in cases {
            let gpo = parse_gpo_with_flags(flags);
            assert_eq!(
                gpo.computer_configuration_enabled(),
                expected,
                "unexpected computer applicability for flags={flags:?}",
            );
        }
    }
}
