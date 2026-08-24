use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;

use crate::modules::gpo::types::{
    GpoError, GppGroupAction, GppGroupMember, GppLocalGroup, GppMemberAction,
};

#[derive(Default)]
struct PendingGroup {
    sid: Option<String>,
    name: Option<String>,
    action: Option<GppGroupAction>,
    disabled: bool,
    delete_all_users: bool,
    delete_all_groups: bool,
    has_item_level_targeting: bool,
    members: Vec<GppGroupMember>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Element {
    Groups,
    Group,
    Properties,
    Members,
    Member,
    Filters,
    Other,
}

impl Element {
    fn from_name(name: &[u8]) -> Self {
        match name {
            b"Groups" => Self::Groups,
            b"Group" => Self::Group,
            b"Properties" => Self::Properties,
            b"Members" => Self::Members,
            b"Member" => Self::Member,
            b"Filters" => Self::Filters,
            _ => Self::Other,
        }
    }
}

/// Parses UTF-8 Group Policy Preferences `Groups.xml` into local-group directives.
/// Empty input represents no directives; malformed documents return an error.
///
/// MS-GPPREF sections 2.2.1.1 and 2.2.1.11.3 define `disabled` on the outer
/// `Groups` and on `Group/Properties`. `Group disabled` is additionally tolerated
/// for compatibility with input accepted by the initial parser. Disabled items
/// are omitted, including when their unused membership attributes are incomplete.
///
/// Item-Level Targeting is detected, not evaluated. A future applicability layer
/// must evaluate it before applying membership; targeted items cannot be applied
/// globally. Unknown subtrees (including `User` and filter contents) are ignored.
pub fn parse_groups_xml(content: &[u8]) -> Result<Vec<GppLocalGroup>, GpoError> {
    use Element::*;

    let mut reader = Reader::from_reader(content);
    reader.config_mut().trim_text(true);
    // Share the same structural checks for <Element/> and <Element></Element>.
    reader.config_mut().expand_empty_elements = true;
    let mut path = Vec::new();
    let mut root_seen = false;
    let mut root_disabled = false;
    let mut groups = Vec::new();
    let mut pending: Option<PendingGroup> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(event)) => {
                let element = Element::from_name(event.local_name().as_ref());
                match (path.as_slice(), element) {
                    ([], Groups) if !root_seen => {
                        root_seen = true;
                        root_disabled = bool_attribute(&event, b"disabled")?;
                    }
                    ([], _) => {
                        return Err(malformed("expected a single Groups root element"));
                    }
                    ([Groups], Group) => {
                        pending = Some(PendingGroup {
                            disabled: root_disabled || bool_attribute(&event, b"disabled")?,
                            ..PendingGroup::default()
                        });
                    }
                    ([Groups, Group], Properties) => {
                        if let Some(group) = pending.as_mut() {
                            group.disabled |= bool_attribute(&event, b"disabled")?;
                            if !group.disabled {
                                if group.action.is_some() {
                                    return Err(malformed("duplicate Group Properties element"));
                                }
                                group.sid = attribute(&event, b"groupSid")?;
                                group.name = attribute(&event, b"groupName")?;
                                group.action = Some(parse_group_action(
                                    attribute(&event, b"action")?.as_deref().unwrap_or("U"),
                                )?);
                                group.delete_all_users = bool_attribute(&event, b"deleteAllUsers")?;
                                group.delete_all_groups =
                                    bool_attribute(&event, b"deleteAllGroups")?;
                            }
                        }
                    }
                    ([Groups, Group, Properties, Members], Member) => {
                        if let Some(group) = pending.as_mut().filter(|group| !group.disabled) {
                            group.members.push(parse_member(&event)?);
                        }
                    }
                    ([Groups, Group], Filters) => {
                        if let Some(group) = pending.as_mut() {
                            group.has_item_level_targeting = true;
                        }
                    }
                    _ => {}
                }
                path.push(element);
            }
            Ok(Event::End(_)) => {
                let element = path.pop();
                if element == Some(Group) && path == [Groups] {
                    let group = pending
                        .take()
                        .ok_or_else(|| malformed("unexpected Group end"))?;
                    if group.disabled {
                        continue;
                    }
                    let action = group
                        .action
                        .ok_or_else(|| malformed("GPP group is missing Properties"))?;
                    let group = GppLocalGroup::new(
                        group.sid,
                        group.name,
                        action,
                        group.delete_all_users,
                        group.delete_all_groups,
                        group.has_item_level_targeting,
                        group.members,
                    );
                    if group.target().is_none() {
                        return Err(malformed("GPP group is missing groupSid and groupName"));
                    }
                    groups.push(group);
                }
            }
            Ok(Event::Text(text)) if !text.is_empty() => {
                return Err(malformed("unexpected text in Groups.xml"));
            }
            Ok(Event::DocType(_) | Event::CData(_)) => {
                return Err(malformed("unsupported DTD or CDATA in Groups.xml"));
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => {
                return Err(malformed(format!(
                    "invalid Groups.xml near byte {}: {error}",
                    reader.error_position()
                )));
            }
        }
    }

    if !path.is_empty() {
        return Err(malformed("unterminated Groups.xml element"));
    }
    Ok(groups)
}

fn malformed(message: impl Into<String>) -> GpoError {
    GpoError::MalformedContent(message.into())
}

fn attribute(event: &BytesStart<'_>, name: &[u8]) -> Result<Option<String>, GpoError> {
    let mut value = None;
    for attribute in event.attributes() {
        let attribute =
            attribute.map_err(|error| malformed(format!("invalid XML attribute: {error}")))?;
        if attribute.key.local_name().as_ref() == name {
            if value.is_some() {
                return Err(malformed("duplicate XML attribute"));
            }
            value = Some(
                attribute
                    .unescape_value()
                    .map_err(|error| malformed(format!("invalid XML attribute value: {error}")))?
                    .into_owned(),
            );
        }
    }
    Ok(value)
}

fn bool_attribute(event: &BytesStart<'_>, name: &[u8]) -> Result<bool, GpoError> {
    match attribute(event, name)?.as_deref().map(str::trim) {
        None | Some("0") => Ok(false),
        Some("1") => Ok(true),
        Some(value) if value.eq_ignore_ascii_case("true") => Ok(true),
        Some(value) if value.eq_ignore_ascii_case("false") => Ok(false),
        _ => Err(malformed("invalid boolean XML attribute")),
    }
}

fn parse_group_action(value: &str) -> Result<GppGroupAction, GpoError> {
    match value {
        value if value.eq_ignore_ascii_case("C") => Ok(GppGroupAction::Create),
        value if value.eq_ignore_ascii_case("D") => Ok(GppGroupAction::Delete),
        value if value.eq_ignore_ascii_case("R") => Ok(GppGroupAction::Replace),
        value if value.eq_ignore_ascii_case("U") => Ok(GppGroupAction::Update),
        _ => Err(malformed(format!("unsupported GPP group action '{value}'"))),
    }
}

fn parse_member(event: &BytesStart<'_>) -> Result<GppGroupMember, GpoError> {
    let action =
        attribute(event, b"action")?.ok_or_else(|| malformed("GPP member is missing action"))?;
    let action = match action.as_str() {
        value if value.eq_ignore_ascii_case("ADD") => GppMemberAction::Add,
        value if value.eq_ignore_ascii_case("REMOVE") => GppMemberAction::Remove,
        value => {
            return Err(malformed(format!(
                "unsupported GPP member action '{value}'"
            )))
        }
    };
    let member = GppGroupMember::new(
        attribute(event, b"sid")?,
        attribute(event, b"name")?,
        action,
    );
    if member.principal().is_none() {
        return Err(malformed("GPP member is missing sid and name"));
    }
    Ok(member)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_item(properties: &str, members: &str) -> Result<Vec<GppLocalGroup>, GpoError> {
        parse_groups_xml(format!(
            "<Groups><Group><Properties {properties}><Members>{members}</Members></Properties></Group></Groups>"
        ).as_bytes())
    }

    #[test]
    fn preserves_sid_precedence_actions_and_targeting() {
        let xml = br#"<?xml version="1.0" encoding="utf-8"?>
<Groups><Group><Properties action="R" groupName="Administrators" groupSid="S-1-5-32-544" deleteAllUsers="1" deleteAllGroups="0"><Members><Member name="DOMAIN\alice" sid="S-1-5-21-1-2-3-1001" action="ADD"/><Member name="DOMAIN\old" action="REMOVE"/></Members></Properties><Filters><FilterOs bool="AND"/></Filters></Group></Groups>"#;
        let groups = parse_groups_xml(xml).unwrap();
        assert_eq!(groups.len(), 1);
        let group = &groups[0];
        assert_eq!(group.target(), Some("S-1-5-32-544"));
        assert_eq!(group.name(), Some("Administrators"));
        assert_eq!(group.action(), GppGroupAction::Replace);
        assert!(group.delete_all_users());
        assert!(!group.delete_all_groups());
        assert!(group.has_item_level_targeting());
        assert_eq!(group.members().len(), 2);
        assert_eq!(group.members()[0].principal(), Some("S-1-5-21-1-2-3-1001"));
        assert_eq!(group.members()[0].action(), GppMemberAction::Add);
        assert_eq!(group.members()[1].action(), GppMemberAction::Remove);
    }

    #[test]
    fn empty_member_sid_falls_back_to_name_without_trimming() {
        for sid in ["", " ", "&#x9;&#xA;&#xD;"] {
            for name in [r"DOMAIN\alice", r" DOMAIN\Help  Desk "] {
                let groups = parse_item(
                    r#"groupName="Administrators""#,
                    &format!(r#"<Member sid="{sid}" name="{name}" action="ADD"/>"#),
                )
                .unwrap();
                let member = &groups[0].members()[0];
                assert_eq!(member.sid(), None);
                assert_eq!(member.principal(), Some(name));
            }
        }
    }

    #[test]
    fn empty_group_sid_falls_back_to_name_without_trimming() {
        for sid in ["", " ", "&#x9;&#xA;&#xD;"] {
            for name in ["Administrators", " Local  Operators "] {
                let groups =
                    parse_item(&format!(r#"groupSid="{sid}" groupName="{name}""#), "").unwrap();
                assert_eq!(groups[0].sid(), None);
                assert_eq!(groups[0].target(), Some(name));
            }
        }
    }

    #[test]
    fn empty_names_are_absent_when_sids_are_present() {
        let groups = parse_item(
            r#"groupSid="S-1-5-32-544" groupName=" ""#,
            r#"<Member sid="S-1-5-21-1-2-3-1001" name="" action="ADD"/>"#,
        )
        .unwrap();
        assert_eq!(groups[0].name(), None);
        assert_eq!(groups[0].members()[0].name(), None);
        assert_eq!(
            groups[0].members()[0].principal(),
            Some("S-1-5-21-1-2-3-1001")
        );
    }

    #[test]
    fn rejects_missing_or_blank_identities() {
        for attributes in ["", r#"sid="" name=" ""#, r#"name="&#x9;""#] {
            assert!(matches!(
                parse_item(
                    r#"groupName="Administrators""#,
                    &format!(r#"<Member {attributes} action="ADD"/>"#)
                ),
                Err(GpoError::MalformedContent(_))
            ));
        }
        for attributes in ["", r#"groupSid="" groupName=" ""#, r#"groupName="&#x9;""#] {
            assert!(matches!(
                parse_item(attributes, ""),
                Err(GpoError::MalformedContent(_))
            ));
        }
    }

    #[test]
    fn root_disabled_suppresses_every_item() {
        for disabled in ["1", "true", "TRUE"] {
            let xml = format!(
                r#"<Groups disabled="{disabled}"><Group><Properties groupName="Administrators"/></Group><Group><Properties groupName="Remote Desktop Users"/></Group></Groups>"#
            );
            assert!(parse_groups_xml(xml.as_bytes()).unwrap().is_empty());
        }
    }

    #[test]
    fn root_enabled_preserves_items() {
        for disabled in ["0", "false", "FALSE"] {
            let xml = format!(
                r#"<Groups disabled="{disabled}"><Group><Properties groupName="Administrators"/></Group></Groups>"#
            );
            assert_eq!(parse_groups_xml(xml.as_bytes()).unwrap().len(), 1);
        }
    }

    #[test]
    fn properties_disabled_suppresses_only_that_item() {
        let xml = br#"<Groups><Group><Properties disabled="1" groupName="Skip"/></Group><Group><Properties disabled="0" groupName="Keep"/></Group></Groups>"#;
        let groups = parse_groups_xml(xml).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].target(), Some("Keep"));
    }

    #[test]
    fn tolerates_group_disabled_without_overriding_properties() {
        let xml = br#"<Groups><Group disabled="1"><Properties disabled="0" groupName="Skip"/></Group><Group disabled="0"><Properties disabled="1" groupName="Skip too"/></Group><Group disabled="0"><Properties groupName="Keep"/></Group></Groups>"#;
        let groups = parse_groups_xml(xml).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].target(), Some("Keep"));
    }

    #[test]
    fn disabled_items_do_not_require_unused_membership_attributes() {
        for xml in [
            r#"<Groups disabled="1"><Group/></Groups>"#,
            r#"<Groups><Group disabled="1"/></Groups>"#,
            r#"<Groups><Group><Properties disabled="1"><Members><Member/></Members></Properties></Group></Groups>"#,
        ] {
            assert!(parse_groups_xml(xml.as_bytes()).unwrap().is_empty());
        }
    }

    #[test]
    fn rejects_invalid_disabled_and_delete_flags() {
        for xml in [
            r#"<Groups disabled="unknown"/>"#,
            r#"<Groups><Group disabled="unknown"/></Groups>"#,
            r#"<Groups><Group><Properties disabled="unknown" groupName="Admins"/></Group></Groups>"#,
            r#"<Groups><Group><Properties groupName="Admins" deleteAllUsers="unknown"/></Group></Groups>"#,
            r#"<Groups><Group><Properties groupName="Admins" deleteAllGroups="unknown"/></Group></Groups>"#,
        ] {
            assert!(matches!(
                parse_groups_xml(xml.as_bytes()),
                Err(GpoError::MalformedContent(_))
            ));
        }
    }

    #[test]
    fn missing_member_action_is_an_error() {
        let result = parse_item(
            r#"groupName="Administrators""#,
            r#"<Member name="DOMAIN\alice"/>"#,
        );
        assert!(
            matches!(result, Err(GpoError::MalformedContent(message)) if message.contains("missing action"))
        );
    }

    #[test]
    fn rejects_unsupported_member_actions() {
        for action in ["", " ", "DELETE", "DEL", "UNKNOWN"] {
            assert!(matches!(
                parse_item(
                    r#"groupName="Administrators""#,
                    &format!(r#"<Member name="DOMAIN\alice" action="{action}"/>"#)
                ),
                Err(GpoError::MalformedContent(_))
            ));
        }
    }

    #[test]
    fn preserves_group_actions_and_defaults_only_missing_action_to_update() {
        for (action, expected) in [
            ("C", GppGroupAction::Create),
            ("D", GppGroupAction::Delete),
            ("R", GppGroupAction::Replace),
            ("U", GppGroupAction::Update),
        ] {
            let groups =
                parse_item(&format!(r#"groupName="Admins" action="{action}""#), "").unwrap();
            assert_eq!(groups[0].action(), expected);
        }
        let groups = parse_item(r#"groupName="Admins""#, "").unwrap();
        assert_eq!(groups[0].action(), GppGroupAction::Update);
        for action in ["", "X"] {
            assert!(matches!(
                parse_item(&format!(r#"groupName="Admins" action="{action}""#), ""),
                Err(GpoError::MalformedContent(_))
            ));
        }
    }

    #[test]
    fn preserves_delete_flags_and_false_defaults() {
        for (attributes, expected) in [
            ("", (false, false)),
            (r#"deleteAllUsers="1""#, (true, false)),
            (r#"deleteAllGroups="1""#, (false, true)),
            (r#"deleteAllUsers="1" deleteAllGroups="1""#, (true, true)),
            (r#"deleteAllUsers="0" deleteAllGroups="0""#, (false, false)),
        ] {
            let groups = parse_item(&format!(r#"groupName="Admins" {attributes}"#), "").unwrap();
            assert_eq!(
                (groups[0].delete_all_users(), groups[0].delete_all_groups()),
                expected
            );
        }
    }

    #[test]
    fn accepts_empty_input_and_empty_groups() {
        for xml in ["", " \r\n", "<Groups/>", "<Groups></Groups>"] {
            assert!(parse_groups_xml(xml.as_bytes()).unwrap().is_empty());
        }
    }

    #[test]
    fn rejects_malformed_truncated_and_multiple_root_documents() {
        for xml in [
            "<",
            "<Groups>",
            "<Groups><Group>",
            r#"<Groups><Group><Properties groupName="Admins"/>"#,
            r#"<Groups><Group><Properties groupName="Admins"/></Group>"#,
            "<Groups><Group></Groups>",
            "<Groups/><Groups/>",
            "<Other/>",
            "not xml",
            "<Groups/>trailing",
            "<Groups><!",
            "<Groups></Groups></Groups>",
        ] {
            assert!(
                matches!(
                    parse_groups_xml(xml.as_bytes()),
                    Err(GpoError::MalformedContent(_))
                ),
                "{xml}"
            );
        }
    }

    #[test]
    fn rejects_missing_or_duplicate_properties() {
        for xml in [
            "<Groups><Group/></Groups>",
            "<Groups><Group></Group></Groups>",
            r#"<Groups><Group><Properties groupName="First"/><Properties groupName="Second"/></Group></Groups>"#,
        ] {
            assert!(matches!(
                parse_groups_xml(xml.as_bytes()),
                Err(GpoError::MalformedContent(_))
            ));
        }
    }

    #[test]
    fn scopes_members_and_targeting_to_the_correct_item() {
        let xml = br#"<Groups><User><Properties userName="Ignored"/></User><Group><Properties groupName="First"><Members><Member name="DOMAIN\alice" action="ADD"></Member></Members></Properties><Filters><Group><Properties groupName="Not a directive"><Members><Member name="DOMAIN\other" action="ADD"/></Members></Properties></Group></Filters></Group><Group><Properties groupName="Second"/><Filters/></Group><Group><Properties groupName="Third"/></Group></Groups>"#;
        let groups = parse_groups_xml(xml).unwrap();
        assert_eq!(
            groups.iter().map(GppLocalGroup::target).collect::<Vec<_>>(),
            vec![Some("First"), Some("Second"), Some("Third")]
        );
        assert_eq!(groups[0].members().len(), 1);
        assert_eq!(groups[0].members()[0].principal(), Some(r"DOMAIN\alice"));
        assert!(groups[0].has_item_level_targeting());
        assert!(groups[1].has_item_level_targeting());
        assert!(!groups[2].has_item_level_targeting());
        assert!(groups[2].members().is_empty());
    }

    #[test]
    fn accepts_namespace_prefixes_and_unescapes_names() {
        let xml = br#"<g:Groups xmlns:g="urn:synthetic:gpp"><g:Group><g:Properties groupName="Local &amp; Operators"><g:Members><g:Member name="DOMAIN\a&amp;b" action="ADD"/></g:Members></g:Properties></g:Group></g:Groups>"#;
        let groups = parse_groups_xml(xml).unwrap();
        assert_eq!(groups[0].target(), Some("Local & Operators"));
        assert_eq!(groups[0].members()[0].principal(), Some(r"DOMAIN\a&b"));
    }

    #[test]
    fn rejects_duplicate_attributes_and_unknown_entities() {
        for properties in [
            r#"groupName="Admins" groupName="Other""#,
            r#"groupName="&unknown;""#,
            r#"groupName="Admins" broken"#,
        ] {
            assert!(matches!(
                parse_item(properties, ""),
                Err(GpoError::MalformedContent(_))
            ));
        }
    }
}
