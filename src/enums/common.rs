/// Map the `groupType` attribute to the scope string BloodHound expects.
///
/// Only the scope bits matter here; `GROUP_TYPE_SECURITY_ENABLED` (0x80000000)
/// distinguishes security from distribution groups and is not part of the scope.
/// <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts>
pub fn group_scope(group_type: i64) -> String {
    const BUILTIN_LOCAL_GROUP: i64 = 0x0000_0001;
    const ACCOUNT_GROUP: i64 = 0x0000_0002;
    const RESOURCE_GROUP: i64 = 0x0000_0004;
    const UNIVERSAL_GROUP: i64 = 0x0000_0008;

    if group_type & UNIVERSAL_GROUP != 0 {
        "Universal".to_string()
    } else if group_type & ACCOUNT_GROUP != 0 {
        "Global".to_string()
    } else if group_type & (RESOURCE_GROUP | BUILTIN_LOCAL_GROUP) != 0 {
        "DomainLocal".to_string()
    } else {
        String::new()
    }
}