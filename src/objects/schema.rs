use std::collections::HashMap;
use ldap3::SearchEntry;
use log::{debug, trace};

use crate::enums::decode_guid_le;

pub struct Schema;

impl Schema {
    /// New Schema
    pub fn new() -> Self {
        Schema
    }

    /// Function to parse value for Schema object.
    pub fn parse(
        &self,
        result: SearchEntry,
        schema_guid_map: &mut HashMap<String, String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        
        let result_dn: String = result.dn.to_uppercase();
        let result_attrs: HashMap<String, Vec<String>> = result.attrs;
        let result_bin: HashMap<String, Vec<Vec<u8>>> = result.bin_attrs;

        // Debug for current object
        debug!("Parse schema: {result_dn}");

        // Trace all result attributes
        for (key, value) in &result_attrs {
            trace!("  {key:?}:{value:?}");
        }
        // Trace all bin result attributes
        for (key, value) in &result_bin {
            trace!("  {key:?}:{value:?}");
        }

        // Only get name:schemaIDGUID
        if let (Some(names), Some(guids)) = (
            result_attrs.get("name"),
            result_bin.get("schemaIDGUID"),
        ) {
            if let (Some(name), Some(guid_bytes)) = (names.first(), guids.first()) {
                let guid = decode_guid_le(guid_bytes);
                trace!("Parse Schema object .to_lowercase(): {}:{}", name.to_lowercase(), guid.to_lowercase());
                schema_guid_map.insert(name.to_lowercase(), guid.to_lowercase());
            }
        }
        
        Ok(())
    }
}