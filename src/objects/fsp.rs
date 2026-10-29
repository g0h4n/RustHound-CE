use serde_json::value::Value;
use serde::{Deserialize, Serialize};
use ldap3::SearchEntry;
use log::{debug, trace};
use std::collections::HashMap;
use std::error::Error;

use crate::enums::decode_guid_le;
use crate::enums::regex::OBJECT_SID_RE1;
use crate::objects::common::{LdapObject, AceTemplate, SPNTarget, Link, Member};
use crate::utils::date::string_to_epoch;
use crate::enums::secdesc::LdapSid;
use crate::enums::sid::{objectsid_to_vec8, sid_maker, guess_object_type_from_str};

/// FSP (ForeignSecurityPrincipal) structure
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Fsp {
    #[serde(rename = "Properties")]
    properties: FspProperties,
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

impl Fsp {
    // New FSP
    pub fn new() -> Self { 
        Self { ..Default::default() } 
    }

    /// Function to parse and replace value in json template for ForeignSecurityPrincipal object.
    pub fn parse(
        &mut self,
        result: SearchEntry,
        domain: &str,
        dn_sid: &mut HashMap<String, String>,
        sid_type: &mut HashMap<String, String>,
        domain_sid: &str
    ) -> Result<(), Box<dyn Error>> {
        let result_dn: String = result.dn.to_uppercase();
        let result_attrs: HashMap<String, Vec<String>> = result.attrs;
        let result_bin: HashMap<String, Vec<Vec<u8>>> = result.bin_attrs;

        // Debug for current object
        debug!("Parse ForeignSecurityPrincipal: {result_dn}");

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

        #[allow(unused_assignments)]
        let mut sid: String = "".to_owned();
        let mut ftype: &str = "Base";

        // With a check
        for (key, value) in &result_attrs {
            match key.as_str() {
                "name" => {
                    let name = format!("{}-{}", domain, &value.first().unwrap_or(&"".to_owned()));
                    self.properties.name = name.to_uppercase();

                    // A FSP name is the SID of the foreign principal. Do not
                    // guess User/Group from the SID: label the well-known
                    // ones and leave the rest as "Base". See #107.
                    ftype = guess_object_type_from_str(&value[0]);
                }
                "whenCreated" => {
                    let epoch = string_to_epoch(&value[0])?;
                    if epoch.is_positive() {
                        self.properties.whencreated = epoch;
                    }
                }
                "objectSid" => {
                    //objectSid to vec and raw to string
                    let vec_sid = objectsid_to_vec8(&value[0]);
                    sid = sid_maker(LdapSid::parse(&vec_sid).unwrap().1, domain);
                    self.object_identifier = sid.to_owned();

                    for domain_sid in OBJECT_SID_RE1.captures_iter(&sid) {
                        self.properties.domainsid = domain_sid[0].to_owned().to_string();
                    }
                }
                "isDeleted" => {
                    self.is_deleted = true;
                }
                _ => {}
            }
        }


        // For all, bins attributs
        for (key, value) in &result_bin {
            match key.as_str() {
                "objectGUID" => {
                    // objectGUID raw to string; the FSP is identified by its SID
                    let guid = decode_guid_le(&value[0]);
                    self.properties.objectguid = guid;
                }
                "objectSid" => {
                    // ldap3 puts objectSid here when it is not valid UTF-8,
                    // which is the case for almost every domain SID
                    let sid = sid_maker(LdapSid::parse(&value[0]).unwrap().1, domain);
                    self.object_identifier = sid.to_owned();

                    for domain_sid in OBJECT_SID_RE1.captures_iter(&sid) {
                        self.properties.domainsid = domain_sid[0].to_owned().to_string();
                    }
                }
                _ => {}
            }
        }

        // Push DN and SID in HashMap
        if self.object_identifier != "SID" {
            dn_sid.insert(
                self.properties.distinguishedname.to_string(),
                self.object_identifier.to_string()
            );
            // Push DN and Type
            sid_type.insert(self.object_identifier.to_string(), ftype.to_string());
        }

        // Trace and return Fsp struct
        // trace!("JSON OUTPUT: {:?}",serde_json::to_string(&self).unwrap());
        Ok(())
    }
}

/// Default FSP properties structure
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct FspProperties {
    domain: String,
    name: String,
    distinguishedname: String,
    domainsid: String,
    objectguid: String,
    doesanyacegrantownerrights: bool,
    doesanyinheritedacegrantownerrights: bool,
    isaclprotected: bool,
    highvalue: bool,
    description: Option<String>,
    whencreated: i64,
}

impl FspProperties {
   // New default properties.
   pub fn new(domain: String) -> Self { 
      Self { 
         domain,
         whencreated: -1,
         ..Default::default() }
   }

   // Immutable access.
   pub fn domain(&self) -> &String {
      &self.domain
   }
   pub fn name(&self) -> &String {
      &self.name
   }
   pub fn distinguishedname(&self) -> &String {
      &self.distinguishedname
   }
   pub fn domainsid(&self) -> &String {
      &self.domainsid
   }
   pub fn highvalue(&self) -> &bool {
      &self.highvalue
   }
   pub fn description(&self) -> &Option<String> {
      &self.description
   }
   pub fn whencreated(&self) -> &i64 {
      &self.whencreated
   }

   // Mutable access.
   pub fn domain_mut(&mut self) -> &mut String {
      &mut self.domain
   }
   pub fn name_mut(&mut self) -> &mut String {
      &mut self.name
   }
   pub fn distinguishedname_mut(&mut self) -> &mut String {
      &mut self.distinguishedname
   }
   pub fn domainsid_mut(&mut self) -> &mut String {
      &mut self.domainsid
   }
   pub fn highvalue_mut(&mut self) -> &mut bool {
      &mut self.highvalue
   }
   pub fn description_mut(&mut self) -> &mut Option<String> {
      &mut self.description
   }
   pub fn whencreated_mut(&mut self) -> &mut i64 {
      &mut self.whencreated
   }
}

impl LdapObject for Fsp {
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

#[cfg(test)]
mod tests {
    use super::Fsp;
    use crate::json::checker::common::replace_sid_members;
    use crate::objects::{common::Member, group::Group};
    use ldap3::SearchEntry;
    use std::collections::HashMap;

    const GUID: [u8; 16] = [
        0x58, 0xEC, 0x7B, 0xF7, 0xA7, 0x73, 0x8D, 0x40,
        0xAF, 0x0D, 0x42, 0xF0, 0xD7, 0x2C, 0x71, 0x14,
    ];
    const GUID_STR: &str = "F77BEC58-73A7-408D-AF0D-42F0D72C7114";

    /// A SID in its binary form: revision 1, authority 5 (NT), sub-authorities.
    fn sid_bytes(sub_authorities: &[u32]) -> Vec<u8> {
        let mut b = vec![1, sub_authorities.len() as u8, 0, 0, 0, 0, 0, 5];
        for s in sub_authorities {
            b.extend_from_slice(&s.to_le_bytes());
        }
        b
    }

    fn parse(entry: SearchEntry) -> (Fsp, HashMap<String, String>) {
        let mut fsp = Fsp::new();
        let mut dn_sid = HashMap::new();
        let mut sid_type = HashMap::new();
        fsp.parse(entry, "example.local", &mut dn_sid, &mut sid_type, "S-1-5-21-1-2-3")
            .unwrap();
        (fsp, dn_sid)
    }

    /// A principal from a trusted forest: ldap3 delivers its objectSid, which
    /// is not valid UTF-8, in bin_attrs.
    fn foreign_principal() -> (String, SearchEntry) {
        let sid = "S-1-5-21-1111111111-2222222222-3333333333-1108";
        let bytes = sid_bytes(&[21, 1111111111, 2222222222, 3333333333, 1108]);
        assert!(std::str::from_utf8(&bytes).is_err(), "delivered in bin_attrs");
        let dn = format!("CN={sid},CN=ForeignSecurityPrincipals,DC=example,DC=local");
        let entry = SearchEntry {
            dn: dn.clone(),
            attrs: HashMap::from([("name".to_string(), vec![sid.to_string()])]),
            bin_attrs: HashMap::from([
                ("objectSid".to_string(), vec![bytes]),
                ("objectGUID".to_string(), vec![GUID.to_vec()]),
            ]),
        };
        (dn.to_uppercase(), entry)
    }

    #[test]
    fn domain_sid_from_bin_attrs_is_the_identifier() {
        let (dn, entry) = foreign_principal();
        let (fsp, dn_sid) = parse(entry);
        let sid = "S-1-5-21-1111111111-2222222222-3333333333-1108";
        assert_eq!(fsp.object_identifier, sid);
        assert_eq!(fsp.properties.objectguid, GUID_STR);
        assert_eq!(fsp.properties.domainsid, "S-1-5-21-1111111111-2222222222-3333333333");
        assert_eq!(dn_sid.get(&dn).map(String::as_str), Some(sid));
    }

    #[test]
    fn well_known_sid_from_attrs_is_not_overwritten_by_the_guid() {
        // S-1-5-11 (Authenticated Users) is valid UTF-8, so ldap3 delivers it
        // in attrs.
        let raw = String::from_utf8(sid_bytes(&[11])).unwrap();
        let entry = SearchEntry {
            dn: "CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=example,DC=local".to_string(),
            attrs: HashMap::from([
                ("name".to_string(), vec!["S-1-5-11".to_string()]),
                ("objectSid".to_string(), vec![raw]),
            ]),
            bin_attrs: HashMap::from([("objectGUID".to_string(), vec![GUID.to_vec()])]),
        };
        let (fsp, _) = parse(entry);
        assert_eq!(fsp.object_identifier, "EXAMPLE.LOCAL-S-1-5-11");
        assert_eq!(fsp.properties.objectguid, GUID_STR);
    }

    #[test]
    fn group_member_from_a_trusted_forest_resolves_to_its_sid() {
        let (dn, entry) = foreign_principal();
        let mut fsp = Fsp::new();
        let mut dn_sid = HashMap::new();
        let mut sid_type = HashMap::new();
        fsp.parse(entry, "example.local", &mut dn_sid, &mut sid_type, "S-1-5-21-1-2-3")
            .unwrap();

        let mut group = Group::new();
        let mut member = Member::new();
        *member.object_identifier_mut() = dn;
        group.members_mut().push(member);
        let mut groups = vec![group];
        replace_sid_members(&mut groups, &dn_sid, &sid_type, &[]).unwrap();

        assert_eq!(
            groups[0].members()[0].object_identifier(),
            "S-1-5-21-1111111111-2222222222-3333333333-1108"
        );
        
        // A foreign domain user must not be asserted as "Group".
        assert_eq!(groups[0].members()[0].object_type(), "Base");
    }
}
