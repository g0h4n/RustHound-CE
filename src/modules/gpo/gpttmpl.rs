use crate::modules::gpo::types::{GpoError, GptTmplPolicy, PrivilegeAssignment};

/// Decodes raw bytes of a GptTmpl.inf security template into a UTF-8 `String`.
///
/// # Encodings
/// - **Canonical protocol encoding**: UTF-16LE with BOM (`0xFF 0xFE`) per Microsoft MS-GPSB section 2.2.
/// - **Additional tolerated encodings**: Defensively accepts UTF-8, UTF-8 with BOM, UTF-16BE with BOM,
///   and UTF-16LE without BOM for collector resilience.
///
/// Rejects incompatible UTF-32 BOMs and truncated/malformed byte sequences with [`GpoError::InvalidEncoding`].
pub fn decode_gpttmpl_bytes(raw: &[u8]) -> Result<String, GpoError> {
    if raw.is_empty() {
        return Ok(String::new());
    }

    // Check for UTF-32 BOMs first to prevent UTF-32LE (0xFF 0xFE 0x00 0x00)
    // from being misidentified as UTF-16LE (0xFF 0xFE).
    if raw.starts_with(&[0x00, 0x00, 0xFE, 0xFF]) {
        return Err(GpoError::InvalidEncoding(
            "Unsupported UTF-32BE encoding".to_string(),
        ));
    }
    if raw.starts_with(&[0xFF, 0xFE, 0x00, 0x00]) {
        return Err(GpoError::InvalidEncoding(
            "Unsupported UTF-32LE encoding".to_string(),
        ));
    }

    // UTF-8 BOM: 0xEF, 0xBB, 0xBF
    if raw.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return std::str::from_utf8(&raw[3..])
            .map(|s| s.to_string())
            .map_err(|e| GpoError::InvalidEncoding(format!("Invalid UTF-8 after BOM: {e}")));
    }

    // UTF-16LE BOM: 0xFF, 0xFE (Canonical per MS-GPSB)
    if raw.starts_with(&[0xFF, 0xFE]) {
        return decode_utf16le(&raw[2..]);
    }

    // UTF-16BE BOM: 0xFE, 0xFF
    if raw.starts_with(&[0xFE, 0xFF]) {
        return decode_utf16be(&raw[2..]);
    }

    // Attempt standard UTF-8 first (valid ASCII is also valid UTF-8)
    if let Ok(s) = std::str::from_utf8(raw) {
        return Ok(s.to_string());
    }

    // If UTF-8 fails and byte length is even, check for UTF-16LE heuristic (common in Windows INF files)
    if raw.len() >= 2 && raw.len() % 2 == 0 && raw[1] == 0 {
        if let Ok(s) = decode_utf16le(raw) {
            return Ok(s);
        }
    }

    Err(GpoError::InvalidEncoding(
        "Unable to decode policy bytes: unrecognized or corrupted character encoding".to_string(),
    ))
}

/// Decodes UTF-16LE byte slice into a String.
fn decode_utf16le(bytes: &[u8]) -> Result<String, GpoError> {
    if bytes.len() % 2 != 0 {
        return Err(GpoError::InvalidEncoding(
            "Truncated UTF-16LE sequence (odd byte count)".to_string(),
        ));
    }

    let u16_units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();

    char::decode_utf16(u16_units)
        .collect::<Result<String, _>>()
        .map_err(|e| GpoError::InvalidEncoding(format!("Invalid UTF-16LE code point: {e}")))
}

/// Decodes UTF-16BE byte slice into a String.
fn decode_utf16be(bytes: &[u8]) -> Result<String, GpoError> {
    if bytes.len() % 2 != 0 {
        return Err(GpoError::InvalidEncoding(
            "Truncated UTF-16BE sequence (odd byte count)".to_string(),
        ));
    }

    let u16_units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
        .collect();

    char::decode_utf16(u16_units)
        .collect::<Result<String, _>>()
        .map_err(|e| GpoError::InvalidEncoding(format!("Invalid UTF-16BE code point: {e}")))
}

/// Parses a decoded `GptTmpl.inf` content string into a structured `GptTmplPolicy`.
/// Returns `Err(GpoError::MalformedContent)` if any syntax error occurs within `[Privilege Rights]`.
///
/// # Comments and Syntax
/// Per Microsoft Windows INF specifications and MS-GPSB section 2.2.6:
/// - Semicolon (`;`) is the comment delimiter.
/// - Character `#` is valid in principal names (e.g. `svc#backup`) and is NOT treated as a comment delimiter.
/// - Empty assignments (e.g. `SeTcbPrivilege = `) represent privileges with zero assigned principals.
pub fn parse_gpttmpl(content: &str) -> Result<GptTmplPolicy, GpoError> {
    let mut current_section: Option<String> = None;
    let mut privilege_rights: Vec<PrivilegeAssignment> = Vec::new();

    for (line_idx, line) in content.lines().enumerate() {
        let line_no = line_idx + 1;
        let trimmed = line.trim();

        // Skip empty lines and full-line comments starting with ';'
        if trimmed.is_empty() || trimmed.starts_with(';') {
            continue;
        }

        // Section header: [Section Name]
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            let section_name = trimmed[1..trimmed.len() - 1].trim();
            current_section = Some(section_name.to_ascii_lowercase());
            continue;
        }

        // Parse section entries
        if let Some(ref section) = current_section {
            if section == "privilege rights" {
                let (raw_key, raw_val) = trimmed.split_once('=').ok_or_else(|| {
                    GpoError::MalformedContent(format!(
                        "invalid privilege assignment at line {line_no}: missing '='"
                    ))
                })?;

                let privilege = raw_key.trim();
                if privilege.is_empty() {
                    return Err(GpoError::MalformedContent(format!(
                        "invalid privilege assignment at line {line_no}: empty privilege name"
                    )));
                }

                // Strip inline comment starting with ';'
                let val_clean = match raw_val.find(';') {
                    Some(idx) => &raw_val[..idx],
                    None => raw_val,
                };

                let mut principals = Vec::new();
                for part in val_clean.split(',') {
                    let principal = part.trim();
                    if !principal.is_empty() && !principals.contains(&principal.to_string()) {
                        principals.push(principal.to_string());
                    }
                }

                // Check if this privilege was already assigned in a previous line
                if let Some(existing) = privilege_rights
                    .iter_mut()
                    .find(|p| p.privilege().eq_ignore_ascii_case(privilege))
                {
                    let mut merged = existing.principals().to_vec();
                    for p in principals {
                        if !merged.contains(&p) {
                            merged.push(p);
                        }
                    }
                    *existing = PrivilegeAssignment::new(existing.privilege().to_string(), merged);
                } else {
                    privilege_rights
                        .push(PrivilegeAssignment::new(privilege.to_string(), principals));
                }
            }
        }
    }

    Ok(GptTmplPolicy::with_privilege_rights(privilege_rights))
}

/// Parses raw bytes of a `GptTmpl.inf` security template directly into a `GptTmplPolicy`.
pub fn parse_gpttmpl_bytes(raw: &[u8]) -> Result<GptTmplPolicy, GpoError> {
    let decoded = decode_gpttmpl_bytes(raw)?;
    parse_gpttmpl(&decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_standard_privilege_rights_synthetic() {
        let content = r#"
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
revision=1
[Privilege Rights]
SeDebugPrivilege = *S-1-5-32-544
SeBackupPrivilege = *S-1-5-21-111-222-333-1001,*S-1-5-32-544
SeRemoteInteractiveLogonRight = *S-1-5-32-555
"#;

        let policy = parse_gpttmpl(content).expect("parsing should succeed");
        assert_eq!(policy.privilege_rights().len(), 3);

        let debug_priv = policy.get_privilege("SeDebugPrivilege").unwrap();
        assert_eq!(debug_priv.principals(), &["*S-1-5-32-544"]);
        assert_eq!(
            debug_priv.normalized_principals().collect::<Vec<_>>(),
            vec!["S-1-5-32-544"]
        );

        let backup_priv = policy.get_privilege("SeBackupPrivilege").unwrap();
        assert_eq!(
            backup_priv.principals(),
            &["*S-1-5-21-111-222-333-1001", "*S-1-5-32-544"]
        );
        assert_eq!(
            backup_priv.sid_candidates().collect::<Vec<_>>(),
            vec!["S-1-5-21-111-222-333-1001", "S-1-5-32-544"]
        );

        let rdp_priv = policy
            .get_privilege("SeRemoteInteractiveLogonRight")
            .unwrap();
        assert_eq!(rdp_priv.principals(), &["*S-1-5-32-555"]);
    }

    #[test]
    fn parse_handles_crlf_and_whitespace_and_comments() {
        let content = "; Header comment\r\n\r\n[Privilege Rights]\r\n  SeImpersonatePrivilege  =  *S-1-5-32-544 , *S-1-5-19  ; inline comment\r\nSeTcbPrivilege = \r\n";
        let policy = parse_gpttmpl(content).expect("parsing should succeed");

        let imp = policy.get_privilege("SeImpersonatePrivilege").unwrap();
        assert_eq!(imp.principals(), &["*S-1-5-32-544", "*S-1-5-19"]);
        assert_eq!(
            imp.sid_candidates().collect::<Vec<_>>(),
            vec!["S-1-5-32-544", "S-1-5-19"]
        );

        let tcb = policy.get_privilege("SeTcbPrivilege").unwrap();
        assert!(tcb.principals().is_empty());
    }

    #[test]
    fn parse_preserves_hash_character_in_principals_per_ms_gpsb() {
        // MS-GPSB section 2.2.6 allows '%' and '#' in PRINCIPALNAMESTRING.
        // '#' must NOT be treated as a comment delimiter.
        let content1 = "[Privilege Rights]\nSeServiceLogonRight = svc#backup\n";
        let policy1 = parse_gpttmpl(content1).unwrap();
        let p1 = policy1.get_privilege("SeServiceLogonRight").unwrap();
        assert_eq!(p1.principals(), &["svc#backup"]);

        // With standard ';' comment after '#' in principal name
        let content2 = "[Privilege Rights]\nSeServiceLogonRight = svc#backup ; valid comment\n";
        let policy2 = parse_gpttmpl(content2).unwrap();
        let p2 = policy2.get_privilege("SeServiceLogonRight").unwrap();
        assert_eq!(p2.principals(), &["svc#backup"]);
    }

    #[test]
    fn parse_rejects_malformed_lines_in_privilege_rights() {
        // Missing '=' delimiter (e.g. colon used instead)
        let bad_content1 = "[Privilege Rights]\nSeDebugPrivilege : *S-1-5-32-544\n";
        let err1 = parse_gpttmpl(bad_content1).unwrap_err();
        match err1 {
            GpoError::MalformedContent(msg) => {
                assert!(msg.contains("line 2"));
                assert!(msg.contains("missing '='"));
            }
            other => panic!("Unexpected error type: {other:?}"),
        }

        // Empty privilege key
        let bad_content2 = "[Privilege Rights]\n = *S-1-5-32-544\n";
        let err2 = parse_gpttmpl(bad_content2).unwrap_err();
        match err2 {
            GpoError::MalformedContent(msg) => {
                assert!(msg.contains("line 2"));
                assert!(msg.contains("empty privilege name"));
            }
            other => panic!("Unexpected error type: {other:?}"),
        }
    }

    #[test]
    fn parse_handles_utf16le_with_bom() {
        let text = "[Privilege Rights]\r\nSeDebugPrivilege = *S-1-5-32-544\r\n";
        let mut bytes = vec![0xFF, 0xFE]; // UTF-16LE BOM
        for u in text.encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }

        let policy =
            parse_gpttmpl_bytes(&bytes).expect("UTF-16LE with BOM should decode and parse");
        let debug_priv = policy.get_privilege("SeDebugPrivilege").unwrap();
        assert_eq!(debug_priv.principals(), &["*S-1-5-32-544"]);
    }

    #[test]
    fn parse_handles_utf16be_with_bom() {
        let text = "[Privilege Rights]\r\nSeSecurityPrivilege = *S-1-5-32-544\r\n";
        let mut bytes = vec![0xFE, 0xFF]; // UTF-16BE BOM
        for u in text.encode_utf16() {
            bytes.extend_from_slice(&u.to_be_bytes());
        }

        let policy =
            parse_gpttmpl_bytes(&bytes).expect("UTF-16BE with BOM should decode and parse");
        let sec_priv = policy.get_privilege("SeSecurityPrivilege").unwrap();
        assert_eq!(sec_priv.principals(), &["*S-1-5-32-544"]);
    }

    #[test]
    fn parse_handles_utf8_with_bom() {
        let text = "[Privilege Rights]\r\nSeTakeOwnershipPrivilege = *S-1-5-32-544\r\n";
        let mut bytes = vec![0xEF, 0xBB, 0xBF]; // UTF-8 BOM
        bytes.extend_from_slice(text.as_bytes());

        let policy = parse_gpttmpl_bytes(&bytes).expect("UTF-8 with BOM should decode and parse");
        let own_priv = policy.get_privilege("SeTakeOwnershipPrivilege").unwrap();
        assert_eq!(own_priv.principals(), &["*S-1-5-32-544"]);
    }

    #[test]
    fn decode_rejects_utf32_boms() {
        let utf32le = vec![0xFF, 0xFE, 0x00, 0x00, 0x5B, 0x00, 0x00, 0x00];
        let err_le = decode_gpttmpl_bytes(&utf32le).unwrap_err();
        match err_le {
            GpoError::InvalidEncoding(msg) => assert!(msg.contains("UTF-32LE")),
            other => panic!("Unexpected error type: {other:?}"),
        }

        let utf32be = vec![0x00, 0x00, 0xFE, 0xFF, 0x00, 0x00, 0x00, 0x5B];
        let err_be = decode_gpttmpl_bytes(&utf32be).unwrap_err();
        match err_be {
            GpoError::InvalidEncoding(msg) => assert!(msg.contains("UTF-32BE")),
            other => panic!("Unexpected error type: {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_invalid_utf16_surrogates() {
        // 0xD800 is an unpaired high surrogate
        let mut bytes = vec![0xFF, 0xFE];
        bytes.extend_from_slice(&0xD800u16.to_le_bytes());
        bytes.extend_from_slice(&0x0020u16.to_le_bytes()); // space

        let err = decode_gpttmpl_bytes(&bytes).unwrap_err();
        match err {
            GpoError::InvalidEncoding(msg) => assert!(msg.contains("Invalid UTF-16LE")),
            other => panic!("Unexpected error type: {other:?}"),
        }
    }

    #[test]
    fn parse_empty_and_missing_sections() {
        let empty_policy = parse_gpttmpl_bytes(b"").unwrap();
        assert!(empty_policy.privilege_rights().is_empty());

        let other_section = "[Version]\r\nsignature=\"$CHICAGO$\"\r\n";
        let policy_other = parse_gpttmpl(other_section).unwrap();
        assert!(policy_other.privilege_rights().is_empty());
    }

    #[test]
    fn parse_handles_duplicates_and_merges() {
        let content = r#"
[Privilege Rights]
SeDebugPrivilege = *S-1-5-32-544, *S-1-5-32-544
SeDebugPrivilege = *S-1-5-32-545
"#;
        let policy = parse_gpttmpl(content).unwrap();
        let debug_priv = policy.get_privilege("SeDebugPrivilege").unwrap();
        assert_eq!(debug_priv.principals(), &["*S-1-5-32-544", "*S-1-5-32-545"]);
    }

    #[test]
    fn parse_arbitrary_unknown_privilege_names_and_non_sid_principals() {
        let content = "[Privilege Rights]\nSeCustomPrivilege = *S-1-5-21-999-888-777-1000, DOMAIN\\CustomGroup\n";
        let policy = parse_gpttmpl(content).unwrap();
        let custom = policy.get_privilege("SeCustomPrivilege").unwrap();
        assert_eq!(
            custom.principals(),
            &["*S-1-5-21-999-888-777-1000", "DOMAIN\\CustomGroup"]
        );
        assert_eq!(
            custom.normalized_principals().collect::<Vec<_>>(),
            vec!["S-1-5-21-999-888-777-1000", "DOMAIN\\CustomGroup"]
        );
        assert_eq!(
            custom.sid_candidates().collect::<Vec<_>>(),
            vec!["S-1-5-21-999-888-777-1000"]
        );
    }

    #[test]
    fn decode_truncated_utf16_returns_error_without_panic() {
        let odd_bytes = vec![0xFF, 0xFE, 0x41]; // 3 bytes (BOM + 1 byte)
        let result = decode_gpttmpl_bytes(&odd_bytes);
        assert!(result.is_err());
        match result.unwrap_err() {
            GpoError::InvalidEncoding(msg) => assert!(msg.contains("Truncated")),
            other => panic!("Unexpected error type: {other:?}"),
        }
    }

    #[test]
    fn parse_handles_mixed_sections_and_case_insensitivity() {
        let content = r#"
[Version]
signature="$CHICAGO$"
revision=1

[PRIVILEGE RIGHTS]
SeAssignPrimaryTokenPrivilege = *S-1-5-19, *S-1-5-20

[Group Membership]
*S-1-5-32-544__Members = *S-1-5-21-1-2-3-500

[System Access]
MinimumPasswordAge = 1
"#;
        let policy = parse_gpttmpl(content).unwrap();
        assert_eq!(policy.privilege_rights().len(), 1);
        let priv_assign = policy
            .get_privilege("SeAssignPrimaryTokenPrivilege")
            .unwrap();
        assert_eq!(priv_assign.principals(), &["*S-1-5-19", "*S-1-5-20"]);
        assert_eq!(
            priv_assign.sid_candidates().collect::<Vec<_>>(),
            vec!["S-1-5-19", "S-1-5-20"]
        );
    }

    #[test]
    fn parse_handles_trailing_comma_and_non_asterisk_sids() {
        let content = r#"
[Privilege Rights]
SeLoadDriverPrivilege = S-1-5-32-544, *S-1-5-32-545,
"#;
        let policy = parse_gpttmpl(content).unwrap();
        let load_driver = policy.get_privilege("SeLoadDriverPrivilege").unwrap();
        assert_eq!(load_driver.principals(), &["S-1-5-32-544", "*S-1-5-32-545"]);
        assert_eq!(
            load_driver.sid_candidates().collect::<Vec<_>>(),
            vec!["S-1-5-32-544", "S-1-5-32-545"]
        );
    }
}
