//! Network transports used by RustHound-CE to talk to Active Directory.
//!
//! * `ldap`: LDAP/LDAPS connection, authentication (NTLM, pass the hash,
//!   Kerberos) and paged search used for the main collection phase.
//! * `smb`: SMB and MS RPC transport (SRVSVC, WKSSVC, WINREG) used by the
//!   sessions module to enumerate live sessions on domain machines.
pub mod ldap;
pub mod smb;