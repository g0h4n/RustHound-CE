//! Pure, Domain-Controller-free logic for the CA-registry collector (issue #97).
//!
//! Everything here is network-free so it unit-tests without a Domain Controller,
//! the same way `modules::webclient::types` keeps its NTSTATUS classification out
//! of the SMB layer. It holds:
//!   * the registry subkeys/values and the bit mask SharpHound reads,
//!   * the DWORD -> bool conversions for IsUserSpecifiesSanEnabled (EditFlags;
//!     BloodHound's ESC6a, and ESC6b together with DCRegistryData) and
//!     RoleSeparationEnabled (an informational CA property; no BloodHound edge
//!     uses it today),
//!   * the `read_value` result classification (REG_DWORD, value absent, or a
//!     real failure), and
//!   * the outcome mapping onto the serialisable (value, failure_reason) pair.
//!
//! Paths, the EditFlags bit, the RoleSeparationEnabled == 1 test and the
//! not-set rule follow SharpHoundCommon v4.9.0 `CertAbuseProcessor` /
//! `SHRegistryKey.GetValue` (`OpenSubKey(subkey)?.GetValue(name)`): a missing
//! key or a missing value reads as Collected:true / Value:false; only a real
//! failure (access denied, connection, timeout) is Collected:false with a
//! FailureReason.

/// `EDITF_ATTRIBUTESUBJECTALTNAME2` — set in the CA policy module `EditFlags`
/// when the CA lets requesters specify an arbitrary SAN (ESC6a/ESC6b).
pub const EDITF_ATTRIBUTESUBJECTALTNAME2: u32 = 0x0004_0000;

/// Registry value names read per Enterprise CA.
pub const EDIT_FLAGS: &str = "EditFlags";
pub const ROLE_SEPARATION_ENABLED: &str = "RoleSeparationEnabled";

/// Root of the CertSvc configuration hive, relative to HKLM.
const CONFIGURATION_ROOT: &str = r"SYSTEM\CurrentControlSet\Services\CertSvc\Configuration";

/// HKLM subkey holding `RoleSeparationEnabled` for `ca_name`.
pub fn configuration_subkey(ca_name: &str) -> String {
    format!(r"{CONFIGURATION_ROOT}\{ca_name}")
}

/// HKLM subkey (the MicrosoftDefault policy module) holding `EditFlags` for
/// `ca_name`.
pub fn policy_module_subkey(ca_name: &str) -> String {
    format!(
        r"{CONFIGURATION_ROOT}\{ca_name}\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy"
    )
}

/// `IsUserSpecifiesSanEnabled` is `EditFlags & EDITF_ATTRIBUTESUBJECTALTNAME2`.
pub fn user_specifies_san_from_editflags(edit_flags: u32) -> bool {
    edit_flags & EDITF_ATTRIBUTESUBJECTALTNAME2 != 0
}

/// `RoleSeparationEnabled` is the DWORD value `1`.
pub fn role_separation_from_dword(value: u32) -> bool {
    value == 1
}

/// The registry type the two values must have.
pub const REG_DWORD: u32 = 4;

/// How a single registry value read turned out, before it becomes a
/// serialisable `(value, failure_reason)` pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueRead {
    /// The REG_DWORD was read successfully.
    Dword(u32),
    /// The key or the value does not exist (ERROR_FILE_NOT_FOUND): as in
    /// SharpHound, a collected default of `false`.
    Absent,
    /// The key/value could not be read (connection, key open, query error,
    /// or a value that is not a REG_DWORD).
    Failed(String),
}

/// Classify a `RegistryClient::read_value` result. Only a REG_DWORD with at
/// least four bytes is a value: dcerpc's `as_dword` reads the first four
/// bytes of any type, so the type is checked here.
pub fn classify_read(res: dcerpc::Result<dcerpc::rrp::RegValue>) -> ValueRead {
    match res {
        Ok(v) if v.ty != REG_DWORD => {
            ValueRead::Failed(format!("expected REG_DWORD, got registry type {}", v.ty))
        }
        Ok(v) => match v.as_dword() {
            Some(d) => ValueRead::Dword(d),
            None => ValueRead::Failed(format!(
                "REG_DWORD value has {} bytes, expected 4",
                v.data.len()
            )),
        },
        Err(e) => classify_read_error(&e.to_string()),
    }
}

/// Classify a `RegistryClient::read_value` error string into a [`ValueRead`].
///
/// dcerpc reports a value that is absent on an opened key as
/// `"BaseRegQueryValue failed (win32 2)"`, and a missing key as
/// `"BaseRegOpenKey('<subkey>') failed (2)"` (both ERROR_FILE_NOT_FOUND); both
/// become [`ValueRead::Absent`], as SharpHound treats them. A connection
/// failure, access denied, or any other error becomes [`ValueRead::Failed`].
pub fn classify_read_error(err: &str) -> ValueRead {
    if is_value_not_found(err) || is_key_not_found(err) {
        ValueRead::Absent
    } else {
        ValueRead::Failed(err.to_string())
    }
}

/// True when the error is a BaseRegOpenKey ERROR_FILE_NOT_FOUND: the subkey
/// does not exist. Matched on the end, so a subkey containing text like
/// "failed (2)" can't fool it, and `(2)` doesn't match `(20)`.
fn is_key_not_found(err: &str) -> bool {
    err.contains("BaseRegOpenKey(") && err.ends_with(") failed (2)")
}

/// True when the error is a BaseRegQueryValue ERROR_FILE_NOT_FOUND, i.e. the key
/// opened but the value does not exist. Matched on the end, like
/// [`is_key_not_found`], so `(win32 2)` doesn't match `(win32 20)`.
fn is_value_not_found(err: &str) -> bool {
    err.ends_with("BaseRegQueryValue failed (win32 2)")
}

/// True when a first `\winreg` open failed with STATUS_PIPE_NOT_AVAILABLE
/// (`0xc00000ac`): the Remote Registry service is trigger-starting, so the
/// collector waits and retries the bind once.
pub fn is_pipe_not_available(err: &str) -> bool {
    err.to_ascii_lowercase().contains("0xc00000ac")
}

/// The serialisable `(value, failure_reason)` pair written back onto the CA;
/// the value is collected exactly when there is no failure reason.
pub type ValueOutcome = (bool, Option<String>);

/// Map an `EditFlags` read to the `IsUserSpecifiesSanEnabled` pair. As in
/// SharpHound, an absent key or value is collected with a default of `false`.
pub fn user_specifies_san_outcome(read: &ValueRead) -> ValueOutcome {
    match read {
        ValueRead::Dword(d) => (user_specifies_san_from_editflags(*d), None),
        ValueRead::Absent => (false, None),
        ValueRead::Failed(e) => (false, Some(e.clone())),
    }
}

/// Map a `RoleSeparationEnabled` read to its pair.
///
/// As in SharpHound, the value is routinely absent on an opened key, which is
/// not a failure: it is collected with a default of `false`.
pub fn role_separation_outcome(read: &ValueRead) -> ValueOutcome {
    match read {
        ValueRead::Dword(d) => (role_separation_from_dword(*d), None),
        ValueRead::Absent => (false, None),
        ValueRead::Failed(e) => (false, Some(e.clone())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CA_NAME: &str = "EXAMPLE-CA";

    #[test]
    fn editflags_bit_test_matches_sharphound() {
        // EDITF_ATTRIBUTESUBJECTALTNAME2 set -> true.
        assert!(user_specifies_san_from_editflags(0x0004_0000));
        // Set alongside other flags still reads as true.
        assert!(user_specifies_san_from_editflags(0x0001_4014 | 0x0004_0000));
        // A typical default EditFlags without the bit -> false.
        assert!(!user_specifies_san_from_editflags(0x0001_4014));
        assert!(!user_specifies_san_from_editflags(0));
    }

    #[test]
    fn role_separation_is_exactly_one() {
        assert!(role_separation_from_dword(1));
        assert!(!role_separation_from_dword(0));
        assert!(!role_separation_from_dword(2));
    }

    #[test]
    fn subkey_paths_are_built_from_the_ca_name() {
        assert_eq!(
            configuration_subkey(CA_NAME),
            r"SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\EXAMPLE-CA"
        );
        assert_eq!(
            policy_module_subkey(CA_NAME),
            r"SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\EXAMPLE-CA\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy"
        );
    }

    #[test]
    fn value_not_found_is_absent_not_a_failure() {
        // dcerpc's exact wording for a missing value on an opened key.
        assert_eq!(
            classify_read_error("BaseRegQueryValue failed (win32 2)"),
            ValueRead::Absent
        );
    }

    #[test]
    fn missing_key_is_absent_as_in_sharphound() {
        // dcerpc's wording (rrp.rs open_key), through RpcError::Protocol's Display.
        let missing = format!(
            "protocol: BaseRegOpenKey('{}') failed (2)",
            policy_module_subkey(CA_NAME)
        );
        assert_eq!(classify_read_error(&missing), ValueRead::Absent);
        // ...and an absent key reads as collected, false.
        assert_eq!(user_specifies_san_outcome(&ValueRead::Absent), (false, None));
    }

    #[test]
    fn other_errors_are_failures() {
        // ERROR_ACCESS_DENIED (5) opening the key is a real failure.
        assert!(matches!(
            classify_read_error("protocol: BaseRegOpenKey('SYSTEM\\x') failed (5)"),
            ValueRead::Failed(_)
        ));
        // "(2)" must not match a longer code such as "(20)".
        assert!(matches!(
            classify_read_error("protocol: BaseRegOpenKey('SYSTEM\\x') failed (20)"),
            ValueRead::Failed(_)
        ));
        // ERROR_ACCESS_DENIED (5) on the query is a real failure.
        assert!(matches!(
            classify_read_error("BaseRegQueryValue failed (win32 5)"),
            ValueRead::Failed(_)
        ));
        // "(win32 2)" must not match a longer code such as "(win32 20)".
        assert!(matches!(
            classify_read_error("BaseRegQueryValue failed (win32 20)"),
            ValueRead::Failed(_)
        ));
        assert!(matches!(
            classify_read_error("open \\winreg: SMB2 status 0xc0000022 for command 0x0005"),
            ValueRead::Failed(_)
        ));
    }

    #[test]
    fn pipe_not_available_is_detected_case_insensitively() {
        assert!(is_pipe_not_available(
            "open \\winreg: SMB2 status 0xc00000ac for command 0x0005"
        ));
        assert!(is_pipe_not_available("protocol: open \\winreg: 0xC00000AC"));
        assert!(!is_pipe_not_available(
            "open \\winreg: SMB2 status 0xc0000022 for command 0x0005"
        ));
    }

    #[test]
    fn user_specifies_san_outcome_mapping() {
        // Success: bit set -> value true, collected (no failure).
        assert_eq!(
            user_specifies_san_outcome(&ValueRead::Dword(0x0004_0000)),
            (true, None)
        );
        // Success: bit clear -> value false, collected.
        assert_eq!(
            user_specifies_san_outcome(&ValueRead::Dword(0x0001_4014)),
            (false, None)
        );
        // As in SharpHound: absent EditFlags -> collected, default false.
        assert_eq!(user_specifies_san_outcome(&ValueRead::Absent), (false, None));
        // Read failure propagates the reason.
        assert_eq!(
            user_specifies_san_outcome(&ValueRead::Failed("boom".into())),
            (false, Some("boom".to_string()))
        );
    }

    #[test]
    fn role_separation_outcome_mapping_and_absent_rule() {
        // value == 1 -> true, collected.
        assert_eq!(role_separation_outcome(&ValueRead::Dword(1)), (true, None));
        // value != 1 -> false, collected.
        assert_eq!(role_separation_outcome(&ValueRead::Dword(0)), (false, None));
        // As in SharpHound: absent value on an opened key -> collected, default false.
        assert_eq!(role_separation_outcome(&ValueRead::Absent), (false, None));
        // A real read failure stays uncollected and carries the reason.
        assert_eq!(
            role_separation_outcome(&ValueRead::Failed("boom".into())),
            (false, Some("boom".to_string()))
        );
    }

    fn reg(ty: u32, data: &[u8]) -> dcerpc::Result<dcerpc::rrp::RegValue> {
        Ok(dcerpc::rrp::RegValue {
            ty,
            data: data.to_vec(),
        })
    }

    #[test]
    fn only_a_reg_dword_is_read_as_a_value() {
        // REG_DWORD, little-endian.
        assert_eq!(
            classify_read(reg(REG_DWORD, &0x0004_0000u32.to_le_bytes())),
            ValueRead::Dword(0x0004_0000)
        );
        // A REG_SZ, REG_BINARY or REG_QWORD of 4+ bytes is not a DWORD.
        for ty in [1, 3, 11] {
            assert!(
                matches!(classify_read(reg(ty, &[0, 0, 4, 0, 0, 0, 0, 0])), ValueRead::Failed(_)),
                "type {ty}"
            );
        }
        // A REG_DWORD shorter than 4 bytes is a failure, not a value.
        assert!(matches!(
            classify_read(reg(REG_DWORD, &[1, 0])),
            ValueRead::Failed(_)
        ));
    }

    #[test]
    fn real_dcerpc_value_not_found_wording_is_absent() {
        // Pins the string match to dcerpc's actual error for
        // BaseRegQueryValue returning ERROR_FILE_NOT_FOUND (2).
        let err = dcerpc::rrp::decode_query_value(&2u32.to_le_bytes()).unwrap_err();
        assert_eq!(classify_read(Err(err)), ValueRead::Absent);
    }
}
