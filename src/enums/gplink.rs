use crate::enums::regex::GPLINK_RE1;
use crate::objects::common::Link;
use std::error::Error;
use std::io::{Error as IoError, ErrorKind};

/// Function to parse gplink and push it in json format
pub fn parse_gplink(all_link: String) -> Result<Vec<Link>, Box<dyn Error>> {
    let mut gplinks: Vec<Link> = Vec::new();
    let mut remaining = all_link.trim();

    while !remaining.is_empty() {
        let entry = remaining
            .strip_prefix('[')
            .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "gPLink entry is missing '['"))?;
        let (entry, rest) = entry
            .split_once(']')
            .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "gPLink entry is missing ']'"))?;
        let (dn, options) = entry
            .rsplit_once(';')
            .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "gPLink entry has no options"))?;
        let guid = GPLINK_RE1
            .find(dn)
            .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "gPLink entry has no GPO GUID"))?;
        let options: u32 = options.parse()?;

        // A disabled link is ignored even when its enforced bit is also set.
        if options & 1 == 0 {
            gplinks.push(Link::new(options & 2 != 0, guid.as_str().to_uppercase()));
        }
        remaining = rest.trim_start();
    }

    Ok(gplinks)
}

#[cfg(test)]
mod tests {
    use super::parse_gplink;

    const FIRST: &str = "11111111-1111-1111-1111-111111111111";
    const SECOND: &str = "22222222-2222-2222-2222-222222222222";
    const THIRD: &str = "33333333-3333-3333-3333-333333333333";
    const FOURTH: &str = "44444444-4444-4444-4444-444444444444";

    fn link(guid: &str, options: u32) -> String {
        format!("[LDAP://CN={{{guid}}},CN=Policies,CN=System,DC=example,DC=org;{options}]")
    }

    #[test]
    fn ignores_disabled_links_and_preserves_active_order() {
        let input = format!(
            "{}{}{}{}",
            link(FIRST, 0),
            link(SECOND, 1),
            link(THIRD, 2),
            link(FOURTH, 3)
        );
        let links = parse_gplink(input).unwrap();

        assert_eq!(links.len(), 2);
        assert_eq!(links[0].guid(), &FIRST.to_string());
        assert!(!links[0].is_enforced());
        assert_eq!(links[1].guid(), &THIRD.to_string());
        assert!(*links[1].is_enforced());
    }

    #[test]
    fn empty_input_has_no_links() {
        assert!(parse_gplink(String::new()).unwrap().is_empty());
    }

    #[test]
    fn malformed_pair_returns_error_without_panicking() {
        let input = format!(
            "{}[LDAP://CN={{{SECOND}}},CN=Policies,CN=System,DC=example,DC=org]",
            link(FIRST, 0)
        );
        assert!(parse_gplink(input).is_err());
    }
}
