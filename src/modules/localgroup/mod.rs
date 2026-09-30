//! Local-group collection module for RustHound-CE  (issue #69 - LocalGroups)
//! <https://bloodhound.specterops.io/resources/edges/admin-to>
//! <https://github.com/g0h4n/LocalGroups-rs>
//!
//! Runs AFTER the LDAP phase, from `modules::run_modules`, and only when the
//! collection method contacts machines (NOT DCOnly / LdapOnly).
//!
//!   SAMR / SamrOpenAlias + SamrGetMembersInAlias -> Computer.LocalGroups
//!
//!   RID 544 Administrators          -> AdminTo
//!   RID 555 Remote Desktop Users    -> CanRDP
//!   RID 562 Distributed COM Users   -> ExecuteDCOM
//!   RID 580 Remote Management Users -> CanPSRemote
//!
//! Same SharpHound-style behaviour as the sessions module: 445 pre-check,
//! active-computer filter, bounded concurrency, no machine contact under
//! DCOnly. Authentication reuses the SMB transport (password, pass the hash,
//! pass the ticket), so nothing new is needed there.

pub mod samr;
pub mod types;

use std::error::Error;
use std::sync::Arc;

use futures::stream::{self, StreamExt};
use log::{debug, info, trace, warn};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};

use smb2_client::SmbClient;
use windows_sddl::sid::Sid;

use crate::args::Options;
use crate::objects::common::{LocalGroup, Member, UserRight};
use crate::objects::computer::Computer;
use crate::objects::user::User;
use crate::transport::smb::{connect_ipc, open_rpc_pipe, smb_user, SmbAuth};

use self::samr::{is_domain_controller, is_under, sid_to_string, SamrAliasClient};
use self::types::{group_display_name, group_object_id, Alias, AliasFinding, HostFindings, ALIASES};

const DEFAULT_CONCURRENCY: usize = 10;
const DEFAULT_PORT_TIMEOUT_MS: u64 = 1_500;
const DEFAULT_HOST_TIMEOUT_MS: u64 = 8_000;
const DEFAULT_EXPIRY_DAYS: i64 = 60;

/// Entry point, called from `modules::run_modules`.
pub async fn run(
    args: &Options,
    _users: &[User], // signature parity with sessions; SAMR returns SIDs
    computers: &mut Vec<Computer>,
    sid_type: &std::collections::HashMap<String, String>,
) -> Result<(), Box<dyn Error>> {
    if !args.collection_method.does_local_group() {
        debug!("[localgroups] collection method does not contact hosts - skipping");
        return Ok(());
    }

    let targets: Vec<(String, String)> = computers
        .iter()
        .filter(|c| is_active(c, DEFAULT_EXPIRY_DAYS))
        .map(|c| (c.properties().name().clone(), c.object_identifier().clone()))
        .collect();

    info!("[localgroups] {} active target(s) after expiry/enabled filter", targets.len());

    let sem = Arc::new(Semaphore::new(DEFAULT_CONCURRENCY));
    let domain = args.domain.clone();
    let user = smb_user(args.username.as_deref().unwrap_or_default());
    let password = args.password.clone().unwrap_or_default();
    let nt_hash = parse_hash(args.hashes.as_deref());

    let kerberos_ccache: Option<String> =
        if args.kerberos { std::env::var("KRB5CCNAME").ok() } else { None };
    let kdc: String = args
        .ldapfqdn
        .clone()
        .filter(|s| !s.is_empty())
        .or_else(|| args.ip.clone())
        .unwrap_or_else(|| args.domain.clone());

    let findings: Vec<HostFindings> = stream::iter(targets)
        .map(|(host, computer_sid)| {
            let (sem, domain, user, password) =
                (sem.clone(), domain.clone(), user.clone(), password.clone());
            let nt_hash = nt_hash;
            let kerberos_ccache = kerberos_ccache.clone();
            let kdc = kdc.clone();
            async move {
                let _permit = sem.acquire().await.unwrap();
                enumerate_host(
                    &host, computer_sid, &domain, &user, &password,
                    nt_hash.as_ref(), kerberos_ccache.as_deref(), &kdc,
                )
                .await
            }
        })
        .buffer_unordered(DEFAULT_CONCURRENCY)
        .collect()
        .await;

    let mut total_edges = 0usize;
    for hf in &findings {
        total_edges += apply_findings(computers, hf, sid_type, &domain);
        for e in &hf.errors {
            warn!("{e}");
        }
    }
    info!("[localgroups] {total_edges} edge(s) across {} host(s)", findings.len());

    Ok(())
}

// Per-host enumeration

#[allow(clippy::too_many_arguments)]
async fn enumerate_host(
    host: &str,
    computer_sid: String,
    domain: &str,
    user: &str,
    password: &str,
    nt_hash: Option<&[u8; 16]>,
    kerberos_ccache: Option<&str>,
    kdc: &str,
) -> HostFindings {
    if !is_reachable(host, DEFAULT_PORT_TIMEOUT_MS).await {
        trace!("[{host}] 445/tcp unreachable - skip");
        return HostFindings {
            computer_sid,
            host: host.to_string(),
            is_dc: false,
            aliases: Vec::new(),
            errors: vec![format!("{host}: 445/tcp unreachable")],
        };
    }

    let work = async {
        let mut aliases: Vec<AliasFinding> = Vec::new();
        let mut errors: Vec<String> = Vec::new();
        let mut is_dc = false;

        let fatal: Result<(), String> = async {
            let mut smb = if let Some(ccache) = kerberos_ccache {
                let spn = format!("cifs/{host}");
                let (gss_blob, session_key) =
                    crate::transport::kerberos::kerberos_material_for(ccache, &spn, kdc)
                        .await
                        .map_err(|e| format!("{host} krb: {e}"))?;
                let auth = SmbAuth::Kerberos { gss_blob: &gss_blob, session_key: &session_key };
                connect_ipc(host, domain, user, auth).await.map_err(|e| format!("{host}: {e}"))?
            } else {
                let auth = match nt_hash {
                    Some(h) => SmbAuth::Hash(h),
                    None => SmbAuth::Password(password),
                };
                connect_ipc(host, domain, user, auth).await.map_err(|e| format!("{host}: {e}"))?
            };

            let (host_aliases, host_errors, dc) =
                samr_local_groups(&mut smb, host, domain, &computer_sid).await;
            aliases = host_aliases;
            errors.extend(host_errors);
            is_dc = dc;
            Ok(())
        }
        .await;

        if let Err(e) = fatal {
            errors.push(e);
        }
        (aliases, errors, is_dc)
    };

    match timeout(Duration::from_millis(DEFAULT_HOST_TIMEOUT_MS), work).await {
        Ok((aliases, errors, is_dc)) => HostFindings {
            computer_sid, host: host.to_string(), is_dc, aliases, errors,
        },
        Err(_elapsed) => HostFindings {
            computer_sid,
            host: host.to_string(),
            is_dc: false,
            aliases: Vec::new(),
            errors: vec![format!("{host}: per-host timeout")],
        },
    }
}

/// The SAMR alias walk over an open IPC$ session.
async fn samr_local_groups(
    smb: &mut SmbClient,
    host: &str,
    domain: &str,
    computer_object_id: &str,
) -> (Vec<AliasFinding>, Vec<String>, bool) {
    let mut out = Vec::new();
    let mut errors = Vec::new();

    let pipe = match open_rpc_pipe(smb, host, "samr").await {
        Ok(p) => p,
        Err(e) => {
            errors.push(format!("{host} \\samr pipe: {e}"));
            return (out, errors, false);
        }
    };
    let mut samr = match SamrAliasClient::bind(smb, pipe).await {
        Ok(c) => c,
        Err(e) => {
            errors.push(format!("{host} SAMR bind: {e}"));
            return (out, errors, false);
        }
    };

    let server = match samr.connect(&format!("\\\\{host}")).await {
        Ok(h) => h,
        Err(e) => {
            errors.push(format!("{host} SamrConnect2: {e}"));
            return (out, errors, false);
        }
    };

    let mut machine_sid: Option<Sid> = None;
    let mut is_dc = false;
    match samr.machine_sid(&server).await {
        Ok(Some((name, sid))) => {
            if is_domain_controller(&name, domain) {
                is_dc = true;
            } else {
                machine_sid = Some(sid);
            }
        }
        Ok(None) => {}
        Err(e) => errors.push(format!("{host} machine SID: {e}")),
    }

    let builtin = match samr.open_builtin(&server).await {
        Ok(h) => h,
        Err(e) => {
            errors.push(format!("{host} SamrOpenDomain(BUILTIN): {e}"));
            let _ = samr.close_handle(&server).await;
            return (out, errors, is_dc);
        }
    };

    for Alias { rid, name: alias_name, .. } in ALIASES {
        let group_sid = group_object_id(*rid, domain, is_dc, computer_object_id);

        let handle = match samr.open_alias(&builtin, *rid).await {
            Ok(h) => h,
            Err(e) => {
                out.push(AliasFinding {
                    group_sid, group_name: alias_name, members: Vec::new(),
                    collected: false, failure: Some(e.to_string()),
                });
                continue;
            }
        };
        let members = match samr.get_members_in_alias(&handle).await {
            Ok(m) => m,
            Err(e) => {
                let _ = samr.close_handle(&handle).await;
                out.push(AliasFinding {
                    group_sid, group_name: alias_name, members: Vec::new(),
                    collected: false, failure: Some(e.to_string()),
                });
                continue;
            }
        };

        // Local accounts have no BloodHound node, so keeping them would create a
        // dangling edge; skipped on a DC where machine_sid is None.
        let kept: Vec<String> = members
            .iter()
            .filter(|m| match &machine_sid {
                Some(mach) => !is_under(m, mach),
                None => true,
            })
            .map(sid_to_string)
            .collect();

        out.push(AliasFinding { group_sid, group_name: alias_name, members: kept, collected: true, failure: None });
        let _ = samr.close_handle(&handle).await;
    }

    let _ = samr.close_handle(&builtin).await;
    let _ = samr.close_handle(&server).await;
    (out, errors, is_dc)
}

/// Write each host's aliases onto the matching Computer. Returns edge count.
/// Member ObjectType comes from `sid_type` (built during the LDAP phase, the
/// same source SharpHound resolves against); "Base" when the SID has no AD
/// object, typically a purely local principal.
fn apply_findings(
    computers: &mut [Computer],
    hf: &HostFindings,
    sid_type: &std::collections::HashMap<String, String>,
    domain: &str,
) -> usize {
    let computer = match computers
        .iter_mut()
        .find(|c| c.object_identifier() == &hf.computer_sid)
    {
        Some(c) => c,
        None => {
            warn!("[localgroups] no computer object for SID {}", hf.computer_sid);
            return 0;
        }
    };

    let mut count = 0usize;
    let groups = computer.local_groups_mut();
    for a in &hf.aliases {
        let mut lg = LocalGroup::new();
        *lg.object_identifier_mut() = a.group_sid.clone();
        *lg.name_mut() = group_display_name(a.group_name, &hf.host, hf.is_dc);
        *lg.collected_mut() = a.collected;
        *lg.failure_reason_mut() = a.failure.clone();
        for sid in &a.members {
            let mut m = Member::new();
            *m.object_identifier_mut() = sid.clone();
            *m.object_type_mut() = sid_type
                .get(sid)
                .cloned()
                .unwrap_or_else(|| "Base".to_string());
            lg.results_mut().push(m);
            count += 1;
        }
        groups.push(lg);
    }
    computer.users_rights_mut().push(
        synth_rdp_userright(&hf.computer_sid, domain, hf.is_dc)
    );
    count
}

// SharpHound synthesizes SeRemoteInteractiveLogonRight = {Administrators, Remote
// Desktop Users} on every machine, because both hold that right by default on
// Windows. No RPC call: the two group ids are the ones we already build for
// LocalGroups. This is what drives CanRDP, on a DC especially.
fn synth_rdp_userright(
    computer_sid: &str,
    domain: &str,
    is_dc: bool,
) -> UserRight {
    let (ty, id544, id555) = if is_dc {
        (
            "Group",
            format!("{}-S-1-5-32-544", domain.to_uppercase()),
            format!("{}-S-1-5-32-555", domain.to_uppercase()),
        )
    } else {
        (
            "ADLocalGroup",
            format!("{computer_sid}-544"),
            format!("{computer_sid}-555"),
        )
    };

    let mut right = UserRight::new();
    *right.privilege_mut() = "SeRemoteInteractiveLogonRight".to_string();
    *right.collected_mut() = true;
    for id in [id544, id555] {
        let mut m = Member::new();
        *m.object_identifier_mut() = id;
        *m.object_type_mut() = ty.to_string();
        right.results_mut().push(m);
    }
    right
}

// Helpers, identical to the sessions module

async fn is_reachable(host: &str, port_timeout_ms: u64) -> bool {
    matches!(
        timeout(
            Duration::from_millis(port_timeout_ms),
            TcpStream::connect(format!("{host}:445"))
        )
        .await,
        Ok(Ok(_))
    )
}

fn is_active(c: &Computer, expiry_days: i64) -> bool {
    if !*c.properties().enabled() {
        return false;
    }
    let pls = c.properties().pwdlastset();
    if pls <= 0 {
        return false;
    }
    let now = chrono::Utc::now().timestamp();
    now - pls < expiry_days * 86_400
}

fn parse_hash(h: Option<&str>) -> Option<[u8; 16]> {
    let raw = h?.trim();
    let nt = raw.rsplit(':').next().unwrap_or(raw).trim();
    if nt.len() != 32 || !nt.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&nt[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_findings_skips_unknown_host() {
        let mut none: Vec<Computer> = vec![];
        let hf = HostFindings {
            computer_sid: "S-1-5-21-1-2-3-1001".to_string(),
            host: "FS01.ESSOS.LOCAL".to_string(),
            is_dc: false,
            aliases: vec![AliasFinding {
                group_sid: "S-1-5-21-1-2-3-544".to_string(),
                group_name: "Administrators",
                members: vec!["S-1-5-21-1-2-3-512".to_string()],
                collected: true,
                failure: None,
            }],
            errors: vec![],
        };
        let domain = "ESSOS.LOCAL";
        assert_eq!(apply_findings(&mut none, &hf, &std::collections::HashMap::new(), domain), 0);
    }

    #[test]
    fn parse_hash_forms() {
        let want = [0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee,
                    0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee];
        assert_eq!(parse_hash(Some("aad3b435b51404eeaad3b435b51404ee")), Some(want));
        assert_eq!(parse_hash(Some(":aad3b435b51404eeaad3b435b51404ee")), Some(want));
        assert_eq!(parse_hash(Some("bad")), None);
        assert_eq!(parse_hash(None), None);
    }
}