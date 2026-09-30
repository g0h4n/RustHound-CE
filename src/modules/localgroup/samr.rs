//! SAMR alias branch: the two opnums the `dcerpc` crate does not ship.
//!
//!   SamrOpenAlias          opnum 27  (MS-SAMR 3.1.5.1.5)
//!   SamrGetMembersInAlias  opnum 33  (MS-SAMR 3.1.5.5.5)
//!
//! Built on dcerpc's public surface (SmbPipe, SamrHandle, the encode_*/decode_*
//! helpers and the NDR layer), so no fork is needed. Only encode_sid/decode_sid
//! are private upstream and are reimplemented here.
//!
//! Read-only: the alias handle is opened with ALIAS_LIST_MEMBERS only.
//!
//! Ported from <https://github.com/g0h4n/LocalGroups-rs> for issue #69.

use anyhow::{Result, anyhow, bail};
use dcerpc::ndr::{NdrDecoder, NdrEncoder};
use dcerpc::samr::{
    SamrHandle, access, decode_enum_domains, decode_lookup_domain, encode_connect2,
    encode_enum_domains, encode_lookup_domain, encode_open_domain, samr_syntax,
};
use dcerpc::transport::SmbPipe;
use dcerpc::RpcError;
use smb2_client::SmbClient;
use windows_sddl::sid::Sid;

// Opnums (MS-SAMR §3.1.4)

pub mod opnum {
    /// SamrOpenAlias(IN domain, IN access, IN rid) -> alias handle.
    pub const OPEN_ALIAS: u16 = 27;
    /// SamrGetMembersInAlias(IN alias) -> SAMPR_PSID_ARRAY_OUT.
    pub const GET_MEMBERS_IN_ALIAS: u16 = 33;
    /// SamrCloseHandle(IN/OUT handle).
    pub const CLOSE_HANDLE: u16 = 1;
}

/// Alias-specific access masks (MS-SAMR §2.2.1.6). Read-only by design.
pub mod alias_access {
    /// ALIAS_LIST_MEMBERS, the only right SamrGetMembersInAlias needs.
    pub const LIST_MEMBERS: u32 = 0x0000_0004;
}

/// The well-known BUILTIN domain SID, `S-1-5-32`.
pub fn builtin_sid() -> Sid {
    Sid { revision: 1, identifier_authority: 5, sub_authorities: vec![32] }
}

// RPC_SID marshaling (private upstream, reimplemented)

/// Encode an RPC_SID. Same bytes as dcerpc's private encode_sid.
/// Only the tests use it today; kept as the counterpart of decode_sid.
#[allow(dead_code)]
fn encode_sid(e: &mut NdrEncoder, sid: &Sid) {
    e.u32(sid.sub_authorities.len() as u32); // max_count
    e.u8(sid.revision);
    e.u8(sid.sub_authorities.len() as u8);
    let a = sid.identifier_authority;
    e.bytes(&[
        (a >> 40) as u8,
        (a >> 32) as u8,
        (a >> 24) as u8,
        (a >> 16) as u8,
        (a >> 8) as u8,
        a as u8,
    ]);
    for s in &sid.sub_authorities {
        e.u32(*s);
    }
}

/// Decode one RPC_SID. max_count is read but never used to allocate: the real
/// count is the 1-byte SubAuthorityCount, capped at 15.
fn decode_sid(d: &mut NdrDecoder) -> Result<Sid> {
    let _max = d.u32()?;
    let revision = d.u8()?;
    let count = d.u8()? as usize;
    if count > 15 {
        bail!("RPC_SID SubAuthorityCount={count} exceeds the 15 allowed by MS-DTYP");
    }
    let auth = d.read_bytes(6)?;
    let identifier_authority = auth.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64);
    let mut sub_authorities = Vec::with_capacity(count);
    for _ in 0..count {
        sub_authorities.push(d.u32()?);
    }
    Ok(Sid { revision, identifier_authority, sub_authorities })
}

// Response tail helper

/// Read the 4-byte NTSTATUS every SAMR reply ends with, before parsing the
/// body, so failures report their real status.
fn tail_status(stub: &[u8], what: &str) -> Result<u32> {
    if stub.len() < 4 {
        bail!("{what}: reply too short ({} bytes, need at least the NTSTATUS)", stub.len());
    }
    let tail = &stub[stub.len() - 4..];
    Ok(u32::from_le_bytes(tail.try_into().unwrap()))
}

/// Explain a DCE/RPC fault. Different code space from NTSTATUS: a fault means
/// the call was refused before SAMR ran, so there is no stub to parse.
pub fn explain_fault(status: u32) -> String {
    match status {
        0x0000_0005 => "nca_s_fault_access_denied: the RPC call was refused before SAMR ran.                         On Win10 1607 / Server 2016 and later the default descriptor grants                         remote SAM to local Administrators only, so a plain domain user is                         denied on a member host. Use an account that is local admin on the                         target, or collect this host's local group membership from GPO instead"
            .to_string(),
        0x0000_0001 => "nca_s_fault_other: the server rejected the request".to_string(),
        _ => format!("RPC fault {status:#010x}, see MS-RPCE appendix for nca_s_* codes"),
    }
}

/// Map the handful of NTSTATUS values worth explaining to the operator.
pub fn explain_status(status: u32) -> &'static str {
    match status {
        0xC000_0022 => "STATUS_ACCESS_DENIED: the account lacks the right to read this alias \
                        (local admin is normally required on a member host)",
        0xC000_0034 => "STATUS_OBJECT_NAME_NOT_FOUND: this BUILTIN alias does not exist on \
                        the target (normal for RID 580 on older/Core builds)",
        0xC000_0060 => "STATUS_SPECIAL_ACCOUNT: the alias is protected on this system",
        0xC000_0008 => "STATUS_INVALID_HANDLE: the domain handle was closed or never opened",
        _           => "see MS-ERREF for this NTSTATUS",
    }
}

// Encoders / decoders for the two missing opnums

/// SamrOpenAlias. Wire layout: handle (20) + access (4) + rid (4).
pub fn encode_open_alias(domain: &SamrHandle, desired_access: u32, rid: u32) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    domain.encode(&mut e);
    e.u32(desired_access);
    e.u32(rid);
    e.into_bytes()
}

/// SamrGetMembersInAlias. Wire layout: handle (20), the rest is [out].
pub fn encode_get_members_in_alias(alias: &SamrHandle) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    alias.encode(&mut e);
    e.into_bytes()
}

/// Decode a `SAMPR_PSID_ARRAY_OUT` reply into the member SIDs.
///
/// ```text
/// typedef struct _SAMPR_PSID_ARRAY_OUT {
///   unsigned long Count;
///   [size_is(Count)] PSAMPR_SID_INFORMATION Sids;   // SAMPR_SID_INFORMATION { PRPC_SID }
/// } SAMPR_PSID_ARRAY_OUT;
/// ```
///
/// Wire order: Count, array pointer, max_count, one pointer per entry, then
/// the SIDs, then the NTSTATUS.
///
/// Count is bounded against the remaining stub before allocating: a SID is at
/// least 12 bytes, so it can never exceed remaining / 12.
pub fn decode_get_members_in_alias(stub: &[u8]) -> Result<Vec<Sid>> {
    let status = tail_status(stub, "SamrGetMembersInAlias")?;
    if status != 0 {
        bail!(
            "SamrGetMembersInAlias failed (NTSTATUS 0x{status:08x}), {}",
            explain_status(status)
        );
    }

    let mut d = NdrDecoder::new(stub);
    let count = d.u32()? as usize;
    let array_ref = d.u32()?;

    if count == 0 || array_ref == 0 {
        // An empty alias is a perfectly valid, meaningful result.
        return Ok(Vec::new());
    }

    // Bound Count against what is actually left in the stub.
    let min_sid_bytes = 12usize; // max_count(4) + rev(1) + subcount(1) + authority(6)
    let budget = d.remaining() / min_sid_bytes;
    if count > budget {
        bail!(
            "SamrGetMembersInAlias: Count={count} exceeds remaining stub \
             ({} bytes, at most {budget} SIDs), truncated or hostile reply",
            d.remaining()
        );
    }

    let max_count = d.u32()? as usize;
    if max_count < count {
        bail!("SamrGetMembersInAlias: conformant max_count={max_count} < Count={count}");
    }

    // One referent id per SAMPR_SID_INFORMATION, all in a row.
    let mut present = Vec::with_capacity(count);
    for _ in 0..count {
        present.push(d.u32()? != 0);
    }

    // Then the deferred RPC_SIDs, in the same order, skipping null pointers.
    let mut sids = Vec::with_capacity(count);
    for is_present in present {
        if is_present {
            sids.push(decode_sid(&mut d)?);
        }
    }
    Ok(sids)
}

// Client

/// SAMR bound over an open \samr pipe, with both the upstream calls and the
/// alias ones.
pub struct SamrAliasClient<'a> {
    pipe: SmbPipe<'a>,
}

impl<'a> SamrAliasClient<'a> {
    /// Bind SAMR. Like dcerpc's SamrClient::bind, but keeps the pipe reachable
    /// so we can call arbitrary opnums.
    pub async fn bind(client: &'a mut SmbClient, file_id: [u8; 16]) -> Result<Self> {
        let mut pipe = SmbPipe::new(client, file_id);
        pipe.bind(samr_syntax()).await.map_err(|e| anyhow!("SAMR bind: {e}"))?;
        Ok(Self { pipe })
    }

    async fn call(&mut self, opnum: u16, stub: &[u8]) -> Result<Vec<u8>> {
        self.pipe.call(opnum, stub).await.map_err(|e| match e {
            // A fault carries its own code space; translate it rather than
            // surfacing a bare hex value the operator has to look up.
            RpcError::Fault(status) => anyhow!("opnum {opnum}: {}", explain_fault(status)),
            other => anyhow!("opnum {opnum}: {other}"),
        })
    }

    /// SamrConnect2 -> server handle.
    pub async fn connect(&mut self, server: &str) -> Result<SamrHandle> {
        let stub = encode_connect2(server, access::MAXIMUM_ALLOWED);
        let resp = self.call(57, &stub).await?;
        let status = tail_status(&resp, "SamrConnect2")?;
        if status != 0 {
            bail!("SamrConnect2 failed (NTSTATUS 0x{status:08x}), {}", explain_status(status));
        }
        let mut d = NdrDecoder::new(&resp);
        SamrHandle::decode(&mut d).map_err(|e| anyhow!("SamrConnect2 handle: {e}"))
    }

    /// SamrOpenDomain on an arbitrary domain SID -> domain handle.
    pub async fn open_domain(&mut self, server: &SamrHandle, sid: &Sid) -> Result<SamrHandle> {
        let stub = encode_open_domain(server, access::MAXIMUM_ALLOWED, sid);
        let resp = self.call(7, &stub).await?;
        let status = tail_status(&resp, "SamrOpenDomain")?;
        if status != 0 {
            bail!("SamrOpenDomain failed (NTSTATUS 0x{status:08x}), {}", explain_status(status));
        }
        let mut d = NdrDecoder::new(&resp);
        SamrHandle::decode(&mut d).map_err(|e| anyhow!("SamrOpenDomain handle: {e}"))
    }

    /// SamrOpenDomain on `S-1-5-32`, the BUILTIN domain that holds the aliases.
    pub async fn open_builtin(&mut self, server: &SamrHandle) -> Result<SamrHandle> {
        self.open_domain(server, &builtin_sid()).await
    }

    /// The host's own domain SID, used as the local-member filter prefix.
    ///
    /// SAMR exposes two domains: Builtin, plus one named after the machine
    /// (member host) or the domain (DC). We look up the second. Mirrors
    /// SharpHound's server.GetMachineSid(), and avoids needing LSA or LDAP.
    ///
    /// On a DC this is the domain SID, see [`is_domain_controller`].
    pub async fn machine_sid(&mut self, server: &SamrHandle) -> Result<Option<(String, Sid)>> {
        let mut resume = 0u32;
        let mut names: Vec<String> = Vec::new();
        loop {
            let stub = encode_enum_domains(server, resume, 0x1000);
            let resp = self.call(6, &stub).await?;
            let status = tail_status(&resp, "SamrEnumerateDomainsInSamServer")?;
            // STATUS_MORE_ENTRIES (0x105) is a success code here.
            if status != 0 && status != 0x0000_0105 {
                bail!(
                    "SamrEnumerateDomainsInSamServer failed (NTSTATUS 0x{status:08x}), {}",
                    explain_status(status)
                );
            }
            let (next, batch) = decode_enum_domains(&resp)
                .map_err(|e| anyhow!("SamrEnumerateDomainsInSamServer decode: {e}"))?;
            names.extend(batch.into_iter().map(|(_rid, n)| n));
            if status != 0x0000_0105 || next == resume {
                break;
            }
            resume = next;
        }

        let Some(local) = names.iter().find(|n| !n.eq_ignore_ascii_case("Builtin")) else {
            return Ok(None);
        };

        let resp = self.call(5, &encode_lookup_domain(server, local)).await?;
        let sid = decode_lookup_domain(&resp)
            .map_err(|e| anyhow!("SamrLookupDomainInSamServer({local}): {e}"))?;
        Ok(Some((local.clone(), sid)))
    }

    /// SamrOpenAlias(rid) with `ALIAS_LIST_MEMBERS` only -> alias handle.
    pub async fn open_alias(&mut self, domain: &SamrHandle, rid: u32) -> Result<SamrHandle> {
        let stub = encode_open_alias(domain, alias_access::LIST_MEMBERS, rid);
        let resp = self.call(opnum::OPEN_ALIAS, &stub).await?;
        let status = tail_status(&resp, "SamrOpenAlias")?;
        if status != 0 {
            bail!(
                "SamrOpenAlias(RID {rid}) failed (NTSTATUS 0x{status:08x}), {}",
                explain_status(status)
            );
        }
        let mut d = NdrDecoder::new(&resp);
        SamrHandle::decode(&mut d).map_err(|e| anyhow!("SamrOpenAlias handle: {e}"))
    }

    /// SamrGetMembersInAlias -> the member SIDs.
    pub async fn get_members_in_alias(&mut self, alias: &SamrHandle) -> Result<Vec<Sid>> {
        let stub = encode_get_members_in_alias(alias);
        let resp = self.call(opnum::GET_MEMBERS_IN_ALIAS, &stub).await?;
        decode_get_members_in_alias(&resp)
    }

    /// SamrCloseHandle, best effort: a leaked handle dies with the pipe.
    pub async fn close_handle(&mut self, handle: &SamrHandle) -> Result<()> {
        let mut e = NdrEncoder::new();
        handle.encode(&mut e);
        let resp = self.call(opnum::CLOSE_HANDLE, &e.into_bytes()).await?;
        let status = tail_status(&resp, "SamrCloseHandle")?;
        if status != 0 {
            bail!("SamrCloseHandle failed (NTSTATUS 0x{status:08x})");
        }
        Ok(())
    }
}

// SID helpers

/// Render a SID in the canonical `S-R-IA-SA1-SA2-...` string form.
pub fn sid_to_string(sid: &Sid) -> String {
    let mut s = format!("S-{}-{}", sid.revision, sid.identifier_authority);
    for sa in &sid.sub_authorities {
        s.push('-');
        s.push_str(&sa.to_string());
    }
    s
}

/// True when `member` belongs to `prefix`'s domain. Compares sub-authorities,
/// not strings, so S-1-5-21-1-2-3 never matches S-1-5-21-1-2-30.
pub fn is_under(member: &Sid, prefix: &Sid) -> bool {
    member.identifier_authority == prefix.identifier_authority
        && member.sub_authorities.len() > prefix.sub_authorities.len()
        && member.sub_authorities[..prefix.sub_authorities.len()] == prefix.sub_authorities[..]
}

/// True when the target looks like a DC, judged from the name SAMR gave its
/// non-BUILTIN domain: the domain's NetBIOS name on a DC, the machine's own
/// name otherwise. Compared against `-d`, reduced to its first label.
///
/// It matters because on a DC that domain's SID is the domain SID, and
/// filtering members under it would empty out every group.
///
/// Heuristic: it breaks when the NetBIOS name differs from the first DNS
/// label. Asking SAMR whether krbtgt exists would be exact.
pub fn is_domain_controller(local_domain_name: &str, cli_domain: &str) -> bool {
    let netbios = cli_domain.split('.').next().unwrap_or(cli_domain);
    local_domain_name.eq_ignore_ascii_case(netbios)
        || local_domain_name.eq_ignore_ascii_case(cli_domain)
}

/// Guess an ObjectType from the SID alone. Well-known SIDs are labelled;
/// domain SIDs come back as "Base" because telling User from Group from
/// Computer needs LDAP. RustHound-CE resolves it at merge time.
pub fn guess_object_type(sid: &Sid) -> &'static str {
    let s = sid_to_string(sid);
    match s.as_str() {
        // Well-known groups that appear constantly in local admin lists.
        "S-1-5-32-544" | "S-1-5-32-545" | "S-1-5-32-555" | "S-1-5-32-562"
        | "S-1-5-32-580" | "S-1-5-11" | "S-1-5-4" | "S-1-1-0" => "Group",
        // Local SYSTEM / LOCAL SERVICE / NETWORK SERVICE.
        "S-1-5-18" | "S-1-5-19" | "S-1-5-20" => "User",
        _ => "Base",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(s: &str) -> Sid {
        let mut parts = s.split('-').skip(1);
        let revision: u8 = parts.next().unwrap().parse().unwrap();
        let identifier_authority: u64 = parts.next().unwrap().parse().unwrap();
        let sub_authorities = parts.map(|p| p.parse().unwrap()).collect();
        Sid { revision, identifier_authority, sub_authorities }
    }

    #[test]
    fn open_alias_layout() {
        let stub = encode_open_alias(&SamrHandle([0; 20]), alias_access::LIST_MEMBERS, 544);
        assert_eq!(stub.len(), 20 + 4 + 4);
        assert_eq!(&stub[20..24], &alias_access::LIST_MEMBERS.to_le_bytes());
        assert_eq!(&stub[24..28], &544u32.to_le_bytes());
    }

    #[test]
    fn get_members_request_is_handle_only() {
        assert_eq!(encode_get_members_in_alias(&SamrHandle([7; 20])).len(), 20);
    }

    /// Build a synthetic SAMPR_PSID_ARRAY_OUT and round-trip it, proves the
    /// nested-pointer / conformant-array decode without a live DC.
    fn encode_members_response(sids: &[Sid]) -> Vec<u8> {
        let mut e = NdrEncoder::new();
        e.u32(sids.len() as u32); // Count
        e.referent(); // Sids array pointer
        e.u32(sids.len() as u32); // conformant max_count
        for _ in sids {
            e.referent(); // SAMPR_SID_INFORMATION.SidPointer
        }
        for s in sids {
            encode_sid(&mut e, s);
        }
        e.u32(0); // NTSTATUS
        e.into_bytes()
    }

    #[test]
    fn members_decode_roundtrip() {
        let members = vec![
            sid("S-1-5-21-1111111111-2222222222-3333333333-512"),
            sid("S-1-5-21-1111111111-2222222222-3333333333-1103"),
            sid("S-1-5-21-4000000000-3900000000-3800000000-500"), // local account
        ];
        let stub = encode_members_response(&members);
        let out = decode_get_members_in_alias(&stub).unwrap();
        let rendered: Vec<String> = out.iter().map(sid_to_string).collect();
        assert_eq!(rendered[0], "S-1-5-21-1111111111-2222222222-3333333333-512");
        assert_eq!(rendered.len(), 3);
    }

    #[test]
    fn empty_alias_is_not_an_error() {
        let stub = encode_members_response(&[]);
        assert!(decode_get_members_in_alias(&stub).unwrap().is_empty());
    }

    #[test]
    fn access_denied_is_reported_as_such() {
        let mut e = NdrEncoder::new();
        e.u32(0);
        e.u32(0);
        e.u32(0xC000_0022); // STATUS_ACCESS_DENIED
        let err = decode_get_members_in_alias(&e.into_bytes()).unwrap_err();
        assert!(err.to_string().contains("ACCESS_DENIED"), "got {err}");
    }

    /// Regression guard: hostile server claims Count = u32::MAX with a
    /// truncated tail. Pre-bound this drove Vec::with_capacity(u32::MAX).
    #[test]
    fn count_is_bounded_against_stub() {
        let mut e = NdrEncoder::new();
        e.u32(u32::MAX); // Count
        e.referent(); // non-null array pointer
        e.u32(0); // NTSTATUS
        let err = decode_get_members_in_alias(&e.into_bytes()).unwrap_err();
        assert!(err.to_string().contains("exceeds remaining stub"), "got {err}");
    }

    #[test]
    fn local_filter_matches_on_subauthorities_not_prefix_string() {
        let machine = sid("S-1-5-21-1-2-3");
        assert!(is_under(&sid("S-1-5-21-1-2-3-500"), &machine));
        // The classic string-prefix bug: -30 must NOT match -3.
        assert!(!is_under(&sid("S-1-5-21-1-2-30-500"), &machine));
        // A domain principal is not under the machine SID.
        assert!(!is_under(&sid("S-1-5-21-7-8-9-1103"), &machine));
    }

    #[test]
    fn builtin_sid_is_s_1_5_32() {
        assert_eq!(sid_to_string(&builtin_sid()), "S-1-5-32");
    }

    /// The group ObjectIdentifier form differs between a member host and a DC.
    /// Confirmed against a live DC (ESSOS.LOCAL lab): emitting
    /// "<domain SID>-544" there fabricates a SID that exists nowhere in AD.
    #[test]
    fn dc_builtin_group_id_is_the_domain_scoped_well_known_principal() {
        let rid = 544u32;
        let machine = "S-1-5-21-1111111111-2222222222-3333333333";
        // Member host: <machine SID>-<rid>
        assert_eq!(format!("{machine}-{rid}"),
                   "S-1-5-21-1111111111-2222222222-3333333333-544");
        // DC: <DOMAIN>-S-1-5-32-<rid>, uppercased
        assert_eq!(format!("{}-S-1-5-32-{rid}", "essos.local".to_uppercase()),
                   "ESSOS.LOCAL-S-1-5-32-544");
    }

    #[test]
    fn dc_is_detected_so_the_local_filter_is_disabled() {
        // On a DC, SAMR names its non-BUILTIN domain after the domain itself.
        assert!(is_domain_controller("CORP", "CORP"));
        assert!(is_domain_controller("CORP", "corp.local"));
        // Live-confirmed case: SAMR reports "ESSOS" for domain ESSOS.LOCAL.
        assert!(is_domain_controller("ESSOS", "ESSOS.LOCAL"));
        // On a member host it is named after the machine.
        assert!(!is_domain_controller("FS01", "CORP"));
        assert!(!is_domain_controller("WKS-042", "corp.local"));
    }
}