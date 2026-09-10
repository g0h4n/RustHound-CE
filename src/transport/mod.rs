//! Network transports used by RustHound-CE to talk to Active Directory.
//!
//! * `ldap`: LDAP/LDAPS connection, authentication (NTLM, pass the hash,
//!   Kerberos) and paged search used for the main collection phase.
//! * `smb`: SMB and MS RPC transport. IPC$ pipes (SRVSVC, WKSSVC, WINREG) for
//!   the sessions module, and the SYSVOL share for GPO file collection.
//! * `gss`: minimal SPNEGO framing for a Kerberos AP-REQ carried in an SMB2
//!   SESSION_SETUP.
//! * `kerberos`: pass the ticket helper. Loads a TGT from a ccache, requests a
//!   cifs/<host> service ticket and builds the AP-REQ for SMB Kerberos auth.
//! * `cert`: rustls client config carrying a client certificate (PFX/PEM) for
//!   certificate authentication over LDAPS.
//! 
pub mod ldap;
pub mod smb;
pub mod gss;
pub mod kerberos;
pub mod cert;