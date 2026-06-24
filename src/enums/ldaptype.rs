use ldap3::SearchEntry;
//use log::trace;

/// Enum to get ldap object type.
pub enum Type {
    User,
    Computer,
    Group,
    Ou,
    Domain,
    Gpo,
    ForeignSecurityPrincipal,
    Container,
    Trust,
    RootCA,
    NtAutStore,
    EnterpriseCA,
    AIACA,
    CertTemplate,
    IssuancePolicie,
    Schema,
    Unknown
}

/// Get object type, like ("user","group","computer","ou", "container", "gpo", "domain" "trust").
pub fn get_type(result: &SearchEntry) -> std::result::Result<Type, Type> {
    let result_attrs = &result.attrs;

    let contains = |values: &Vec<String>, to_find: &str| values.iter().any(|elem| elem == to_find);
    let object_class_vals = result_attrs.get("objectClass");
    let flags_vals = result_attrs.get("flags");

    if let Some(vals) = object_class_vals {
        match () {
            _ if contains(vals, "person")
                && contains(vals, "user")
                && !contains(vals, "computer")
                && !contains(vals, "group") => {
                return Ok(Type::User);
            }
            _ if contains(vals, "msDS-GroupManagedServiceAccount") => {
                return Ok(Type::User);
            }
            _ if contains(vals, "group") => {
                return Ok(Type::Group);
            }
            _ if contains(vals, "computer") => {
                return Ok(Type::Computer);
            }
            _ if contains(vals, "organizationalUnit") => {
                return Ok(Type::Ou);
            }
            _ if contains(vals, "domain") => {
                return Ok(Type::Domain);
            }
            _ if contains(vals, "groupPolicyContainer") => {
                return Ok(Type::Gpo);
            }
            _ if contains(vals, "top")
                && contains(vals, "foreignSecurityPrincipal") => {
                return Ok(Type::ForeignSecurityPrincipal);
            }
            _ if contains(vals, "top") && contains(vals, "container")
                && !contains(vals, "groupPolicyContainer") => {
                return Ok(Type::Container);
            }
            _ if contains(vals, "trustedDomain") => {
                return Ok(Type::Trust);
            }
            _ if contains(vals, "certificationAuthority")
                && result.dn.contains(DirectoryPaths::ROOT_CA_LOCATION) => {
                return Ok(Type::RootCA);
            }
            _ if contains(vals, "pKIEnrollmentService")
                && result.dn.contains(DirectoryPaths::ENTERPRISE_CA_LOCATION) => {
                return Ok(Type::EnterpriseCA);
            }
            _ if contains(vals, "pKICertificateTemplate")
                && result.dn.contains(DirectoryPaths::CERT_TEMPLATE_LOCATION) => {
                return Ok(Type::CertTemplate);
            }
            _ if contains(vals, "certificationAuthority")
                && result.dn.contains(DirectoryPaths::AIA_CA_LOCATION) => {
                return Ok(Type::AIACA);
            }
            _ if contains(vals, "certificationAuthority")
                && result.dn.contains(DirectoryPaths::NT_AUTH_STORE_LOCATION) => {
                return Ok(Type::NtAutStore);
            }
            _ if contains(vals, "msPKI-Enterprise-Oid")
                && result.dn.contains(DirectoryPaths::ISSUANCE_LOCATION) => {
                if let Some(flags) = flags_vals {
                    if contains(flags, "2") {
                        return Ok(Type::IssuancePolicie);
                    }
                }
            }
            _ if contains(vals, "attributeSchema") 
                || contains(vals, "classSchema") => {
                return Ok(Type::Schema);
            }
            _ => {}
        }
    }
    Err(Type::Unknown)
}

/// Ldap directory path.
pub struct DirectoryPaths;

impl DirectoryPaths {
    pub const ENTERPRISE_CA_LOCATION    : &'static str = "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration";
    pub const ROOT_CA_LOCATION          : &'static str = "CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration";
    pub const AIA_CA_LOCATION           : &'static str = "CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration";
    pub const CERT_TEMPLATE_LOCATION    : &'static str = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration";
    pub const NT_AUTH_STORE_LOCATION    : &'static str = "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration";
    pub const PKI_LOCATION              : &'static str = "CN=Public Key Services,CN=Services,CN=Configuration";
    pub const CONFIG_LOCATION           : &'static str = "CN=Configuration";
    pub const ISSUANCE_LOCATION         : &'static str = "CN=OID,CN=Public Key Services,CN=Services,CN=Configuration";
}