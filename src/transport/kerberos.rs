//! Kerberos pass-the-ticket for the SMB transport.
//!
//! Loads a TGT from an MIT ccache (KRB5CCNAME), requests a cifs/<host> service
//! ticket, and builds a SPNEGO AP-REQ plus the 16-byte SMB session key for
//! SmbClient::login_kerberos. Pure Rust: a small self-contained ccache v4
//! parser plus picky-krb, no external ccache crate and no system GSSAPI.
//! The TGS/AP-REQ logic is ported from icedracon/adhammer. <https://github.com/icedracon/adhammer>
//!
//! Logging discipline: only lengths, etypes, realm and SPN are logged (the
//! realm/SPN already travel in clear on the wire). Session keys, subkeys and
//! ticket/AP-REQ bytes are never logged.

use anyhow::{anyhow, Context, Result};
use log::{debug, trace, warn};

use picky_asn1::bit_string::BitString;
use picky_asn1::date::Date;
use picky_asn1::restricted_string::Ia5String;
use picky_asn1::wrapper::{
    Asn1SequenceOf, BitStringAsn1, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2,
    ExplicitContextTag3, ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag6,
    ExplicitContextTag7, ExplicitContextTag8, GeneralStringAsn1, IntegerAsn1, OctetStringAsn1,
    Optional,
};
use picky_krb::constants::key_usages::{
    TGS_REP_ENC_SESSION_KEY, TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR,
};
use picky_krb::constants::types::{AP_REQ_MSG_TYPE, NT_SRV_INST, TGS_REQ_MSG_TYPE};
use picky_krb::crypto::{Cipher, CipherSuite};
use picky_krb::data_types::{
    Authenticator, AuthenticatorInner, Checksum, EncryptedData, EncryptionKey, KerberosTime,
    PaData, PrincipalName, Ticket,
};
use picky_krb::messages::{
    ApReq, ApReqInner, EncAsRepPart, EncTgsRepPart, KdcReq, KdcReqBody, KrbError, TgsRep, TgsReq,
};

const ETYPE_RC4_HMAC: u8 = 23;
const ETYPE_AES256: u8 = 18;
const PA_TGS_REQ: u8 = 0x01;

/// Entry point: read the ccache, get a service ticket for `spn`, and return the
/// SPNEGO AP-REQ blob plus the 16-byte SMB session key for login_kerberos.
///
/// `spn` is "cifs/<target-fqdn>"; `kdc` is the KDC host (DC FQDN or IP), port 88.
pub async fn kerberos_material_for(
    ccache_path: &str,
    spn: &str,
    kdc: &str,
) -> Result<(Vec<u8>, [u8; 16])> {
    let path = ccache_path.strip_prefix("FILE:").unwrap_or(ccache_path);
    debug!("[krb] pass-the-ticket for {spn} via {kdc} (ccache: {path})");

    let bytes = std::fs::read(path).with_context(|| format!("read ccache {path}"))?;
    trace!("[krb] ccache read: {} bytes", bytes.len());
    let creds = parse_ccache(&bytes)?;
    trace!("[krb] ccache parsed: {} credential(s)", creds.len());

    let tgt_cred = creds
        .iter()
        .find(|c| {
            c.server
                .components
                .first()
                .map(|c0| c0.eq_ignore_ascii_case(b"krbtgt"))
                .unwrap_or(false)
        })
        .ok_or_else(|| {
            warn!("[krb] no krbtgt credential in ccache ({} creds)", creds.len());
            anyhow!("no TGT (krbtgt) found in ccache")
        })?;

    let realm = String::from_utf8_lossy(&tgt_cred.client.realm).to_string();
    let comps: Vec<String> = tgt_cred
        .client
        .components
        .iter()
        .map(|c| String::from_utf8_lossy(c).to_string())
        .collect();
    debug!(
        "[krb] TGT for {}@{} (session key {} bytes)",
        comps.join("/"),
        realm,
        tgt_cred.key.len()
    );

    let tgt = Tgt::from_ccache_parts(
        &tgt_cred.ticket,
        tgt_cred.key.clone(),
        tgt_cred.client.name_type,
        &comps,
        realm,
    )?;

    let st = get_service_ticket(&tgt, spn, kdc).await?;
    let (gss_blob, session_key) = build_ap_req_gss(&st)?;
    debug!(
        "[krb] AP-REQ ready for {spn}: SPNEGO {} bytes, SMB session key {} bytes",
        gss_blob.len(),
        session_key.len()
    );
    Ok((gss_blob, session_key))
}

// ---- MIT ccache v4 parser (self-contained, no external crate) ---------------

struct CcachePrincipal {
    name_type: u32,
    realm: Vec<u8>,
    components: Vec<Vec<u8>>,
}
struct CcacheCred {
    server: CcachePrincipal,
    client: CcachePrincipal,
    key: Vec<u8>,
    ticket: Vec<u8>,
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let s = self
            .b
            .get(self.pos..self.pos + n)
            .ok_or_else(|| anyhow!("ccache truncated at offset {}", self.pos))?;
        self.pos += n;
        Ok(s)
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    /// uint32 length + bytes.
    fn data(&mut self) -> Result<Vec<u8>> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn principal(&mut self) -> Result<CcachePrincipal> {
        let name_type = self.u32()?;
        let num = self.u32()? as usize; // component count (v4: realm is separate)
        let realm = self.data()?;
        let mut components = Vec::with_capacity(num);
        for _ in 0..num {
            components.push(self.data()?);
        }
        Ok(CcachePrincipal { name_type, realm, components })
    }
}

/// Parse an MIT ccache v4 (0x0504) and return its credentials.
fn parse_ccache(bytes: &[u8]) -> Result<Vec<CcacheCred>> {
    let mut r = Reader::new(bytes);
    let version = r.u16()?;
    if version != 0x0504 {
        return Err(anyhow!(
            "unsupported ccache version {version:#06x} (need v4 0x0504)"
        ));
    }
    trace!("[krb] ccache v4 header ok");
    // v4 header block: uint16 header_len + tagged fields (skip it).
    let hlen = r.u16()? as usize;
    r.take(hlen)?;
    // default principal.
    let _default = r.principal()?;
    // credentials until EOF.
    let mut creds = Vec::new();
    while r.pos < bytes.len() {
        let client = r.principal()?;
        let server = r.principal()?;
        // keyblock: uint16 keytype, uint16 etype, uint16 keylen, key.
        let _keytype = r.u16()?;
        let _etype = r.u16()?;
        let klen = r.u16()? as usize;
        let key = r.take(klen)?.to_vec();
        // times: authtime, starttime, endtime, renew_till.
        let _ = (r.u32()?, r.u32()?, r.u32()?, r.u32()?);
        let _is_skey = r.u8()?;
        let _tktflags = r.u32()?;
        // addresses.
        let na = r.u32()? as usize;
        for _ in 0..na {
            let _t = r.u16()?;
            let _ = r.data()?;
        }
        // authdata.
        let nad = r.u32()? as usize;
        for _ in 0..nad {
            let _t = r.u16()?;
            let _ = r.data()?;
        }
        // ticket + second_ticket.
        let ticket = r.data()?;
        let _second = r.data()?;
        trace!(
            "[krb] ccache cred: server={}",
            server
                .components
                .iter()
                .map(|c| String::from_utf8_lossy(c).to_string())
                .collect::<Vec<_>>()
                .join("/")
        );
        creds.push(CcacheCred { server, client, key, ticket });
    }
    Ok(creds)
}

// ---- crypto helpers ----------------------------------------------------------

fn aes256() -> Box<dyn Cipher> {
    CipherSuite::Aes256CtsHmacSha196.cipher()
}
fn session_etype(key: &[u8]) -> u8 {
    if key.len() == 16 { ETYPE_RC4_HMAC } else { ETYPE_AES256 }
}
fn enc_session(key: &[u8], usage: i32, data: &[u8]) -> Result<Vec<u8>> {
    if key.len() == 16 {
        Ok(ms_pac_forge::checksum::rc4_encrypt(key, usage, data, None))
    } else {
        aes256().encrypt(key, usage, data).map_err(|e| anyhow!("encrypt (AES): {e}"))
    }
}
fn dec_session(key: &[u8], usage: i32, ct: &[u8]) -> Result<Vec<u8>> {
    if key.len() == 16 {
        ms_pac_forge::checksum::rc4_decrypt(key, usage, ct).map_err(|e| anyhow!("decrypt (RC4): {e}"))
    } else {
        aes256().decrypt(key, usage, ct).map_err(|e| anyhow!("decrypt (AES): {e}"))
    }
}

// ---- ASN.1 helpers ------------------------------------------------------------

fn krb_string(s: &str) -> Result<GeneralStringAsn1> {
    let ia5 = Ia5String::from_string(s.to_owned())
        .map_err(|_| anyhow!("non-IA5 Kerberos component: {s:?}"))?;
    Ok(GeneralStringAsn1::from(ia5))
}
fn principal(name_type: u8, parts: &[&str]) -> Result<PrincipalName> {
    let strings = parts.iter().map(|p| krb_string(p)).collect::<Result<Vec<_>>>()?;
    Ok(PrincipalName {
        name_type: ExplicitContextTag0::from(IntegerAsn1(vec![name_type])),
        name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(strings)),
    })
}
fn now_kerberos_time() -> KerberosTime {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let tod = secs.rem_euclid(86_400);
    KerberosTime::from(
        Date::new(y, m, d, (tod / 3600) as u8, ((tod % 3600) / 60) as u8, (tod % 60) as u8).unwrap(),
    )
}
fn far_future_time() -> KerberosTime {
    KerberosTime::from(Date::new(2037, 9, 13, 2, 48, 5).unwrap())
}
fn civil_from_days(z: i64) -> (u16, u8, u8) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    ((y + i64::from(m <= 2)) as u16, m as u8, d as u8)
}
fn nonce() -> IntegerAsn1 {
    let mut n = [0u8; 4];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut n);
    n[0] &= 0x7f;
    IntegerAsn1(n.to_vec())
}
fn encrypted_data(etype: u8, cipher: Vec<u8>) -> EncryptedData {
    EncryptedData {
        etype: ExplicitContextTag0::from(IntegerAsn1(vec![etype])),
        kvno: Optional::from(None),
        cipher: ExplicitContextTag2::from(OctetStringAsn1(cipher)),
    }
}
fn krb_err(resp: &[u8]) -> String {
    match picky_asn1_der::from_bytes::<KrbError>(resp) {
        Ok(err) => format!("KDC error {}", err.0.error_code.0),
        Err(e) => format!("decode: {e}"),
    }
}

// ---- KDC network exchange (TCP/88) --------------------------------------------

async fn kdc_exchange(kdc: &str, request: &[u8]) -> Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let addr = if kdc.contains(':') { kdc.to_string() } else { format!("{kdc}:88") };

    trace!("[krb] KDC connect {addr}, sending {} bytes", request.len());
    let mut stream = tokio::net::TcpStream::connect(&addr).await.map_err(|e| {
        warn!("[krb] KDC connect {addr} failed: {e}");
        e
    })?;
    let mut framed = Vec::with_capacity(request.len() + 4);
    framed.extend_from_slice(&(request.len() as u32).to_be_bytes());
    framed.extend_from_slice(request);
    stream.write_all(&framed).await?;

    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await?;
    let n = u32::from_be_bytes(len) as usize;
    if n == 0 || n > 4 * 1024 * 1024 {
        return Err(anyhow!("implausible KDC response length {n}"));
    }
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).await?;
    trace!("[krb] KDC response: {} bytes", n);
    Ok(buf)
}

// ---- Tgt / ServiceTicket ------------------------------------------------------

struct Tgt {
    ticket: Ticket,
    session_key: Vec<u8>,
    cname: PrincipalName,
    crealm: String,
}

impl Tgt {
    fn from_ccache_parts(
        ticket_der: &[u8],
        session_key: Vec<u8>,
        name_type: u32,
        components: &[String],
        realm: String,
    ) -> Result<Self> {
        let ticket: Ticket = picky_asn1_der::from_bytes(ticket_der)
            .map_err(|e| anyhow!("decode ticket DER: {e}"))?;
        let parts: Vec<&str> = components.iter().map(|s| s.as_str()).collect();
        let cname = principal(name_type as u8, &parts)?;
        Ok(Tgt { ticket, session_key, cname, crealm: realm })
    }
}

struct ServiceTicket {
    ticket: Ticket,
    session_key: Vec<u8>,
    crealm: String,
    cname: PrincipalName,
}

// ---- TGS-REQ + AP-REQ ---------------------------------------------------------

fn ap_req_padata(tgt: &Tgt) -> Result<PaData> {
    let authenticator = Authenticator::from(AuthenticatorInner {
        authenticator_vno: ExplicitContextTag0::from(IntegerAsn1(vec![5])),
        crealm: ExplicitContextTag1::from(krb_string(&tgt.crealm)?),
        cname: ExplicitContextTag2::from(tgt.cname.clone()),
        cksum: Optional::from(None),
        cusec: ExplicitContextTag4::from(IntegerAsn1(vec![0])),
        ctime: ExplicitContextTag5::from(now_kerberos_time()),
        subkey: Optional::from(None),
        seq_number: Optional::from(None),
        authorization_data: Optional::from(None),
    });
    let auth_der = picky_asn1_der::to_vec(&authenticator).map_err(|e| anyhow!("authenticator: {e}"))?;
    let enc_auth = enc_session(&tgt.session_key, TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR, &auth_der)?;
    let ap_req = ApReq::from(ApReqInner {
        pvno: ExplicitContextTag0::from(IntegerAsn1(vec![5])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1(vec![AP_REQ_MSG_TYPE])),
        ap_options: ExplicitContextTag2::from(BitStringAsn1::from(BitString::with_bytes(vec![0, 0, 0, 0]))),
        ticket: ExplicitContextTag3::from(tgt.ticket.clone()),
        authenticator: ExplicitContextTag4::from(encrypted_data(session_etype(&tgt.session_key), enc_auth)),
    });
    let ap_der = picky_asn1_der::to_vec(&ap_req).map_err(|e| anyhow!("AP-REQ: {e}"))?;
    Ok(PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1(vec![PA_TGS_REQ])),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1(ap_der)),
    })
}

fn build_tgs_req(realm: &str, sname: PrincipalName, padatas: Vec<PaData>, etypes: &[u8]) -> Result<TgsReq> {
    let body = KdcReqBody {
        kdc_options: ExplicitContextTag0::from(BitStringAsn1::from(BitString::with_bytes(vec![0x40, 0x81, 0x00, 0x00]))),
        cname: Optional::from(None),
        realm: ExplicitContextTag2::from(krb_string(realm)?),
        sname: Optional::from(Some(ExplicitContextTag3::from(sname))),
        from: Optional::from(None),
        till: ExplicitContextTag5::from(far_future_time()),
        rtime: Optional::from(None),
        nonce: ExplicitContextTag7::from(nonce()),
        etype: ExplicitContextTag8::from(Asn1SequenceOf::from(
            etypes.iter().map(|e| IntegerAsn1(vec![*e])).collect::<Vec<_>>(),
        )),
        addresses: Optional::from(None),
        enc_authorization_data: Optional::from(None),
        additional_tickets: Optional::from(None),
    };
    Ok(TgsReq::from(KdcReq {
        pvno: ExplicitContextTag1::from(IntegerAsn1(vec![5])),
        msg_type: ExplicitContextTag2::from(IntegerAsn1(vec![TGS_REQ_MSG_TYPE])),
        padata: Optional::from(Some(ExplicitContextTag3::from(Asn1SequenceOf::from(padatas)))),
        req_body: ExplicitContextTag4::from(body),
    }))
}

async fn get_service_ticket(tgt: &Tgt, spn: &str, kdc: &str) -> Result<ServiceTicket> {
    debug!("[krb] TGS-REQ for {spn} (realm {})", tgt.crealm);
    let comps: Vec<&str> = spn.split('/').collect();
    let req = build_tgs_req(
        &tgt.crealm,
        principal(NT_SRV_INST, &comps)?,
        vec![ap_req_padata(tgt)?],
        &[ETYPE_AES256, ETYPE_RC4_HMAC],
    )?;
    let raw = picky_asn1_der::to_vec(&req).map_err(|e| anyhow!("TGS-REQ encode: {e}"))?;
    let resp = kdc_exchange(kdc, &raw).await?;

    let tgs_rep: TgsRep = picky_asn1_der::from_bytes(&resp).map_err(|_| {
        let err = krb_err(&resp);
        warn!("[krb] TGS-REP error for {spn}: {err}");
        anyhow!("TGS-REP: {err}")
    })?;

    let enc = &tgs_rep.0.enc_part.0.cipher.0 .0;
    let plain = dec_session(&tgt.session_key, TGS_REP_ENC_SESSION_KEY, enc)?;
    let kdc_rep = picky_asn1_der::from_bytes::<EncTgsRepPart>(&plain)
        .map(|p| p.0)
        .or_else(|_| picky_asn1_der::from_bytes::<EncAsRepPart>(&plain).map(|p| p.0))
        .map_err(|e| anyhow!("decode EncKDCRepPart: {e}"))?;
    let session_key = kdc_rep.key.0.key_value.0 .0.clone();
    debug!(
        "[krb] service ticket for {spn}: session key {} bytes (etype {})",
        session_key.len(),
        session_etype(&session_key)
    );

    Ok(ServiceTicket {
        ticket: tgs_rep.0.ticket.0.clone(),
        session_key,
        crealm: tgt.crealm.clone(),
        cname: tgt.cname.clone(),
    })
}

fn build_ap_req_gss(st: &ServiceTicket) -> Result<(Vec<u8>, [u8; 16])> {
    let mut subkey = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut subkey);
    trace!(
        "[krb] building AP-REQ (fresh AES128 subkey, service etype {})",
        session_etype(&st.session_key)
    );

    let mut gss_cksum = Vec::new();
    gss_cksum.extend_from_slice(&16u32.to_le_bytes());
    gss_cksum.extend_from_slice(&[0u8; 16]);
    gss_cksum.extend_from_slice(&0x0000_003cu32.to_le_bytes());

    let authenticator = Authenticator::from(AuthenticatorInner {
        authenticator_vno: ExplicitContextTag0::from(IntegerAsn1(vec![5])),
        crealm: ExplicitContextTag1::from(krb_string(&st.crealm)?),
        cname: ExplicitContextTag2::from(st.cname.clone()),
        cksum: Optional::from(Some(ExplicitContextTag3::from(Checksum {
            cksumtype: ExplicitContextTag0::from(IntegerAsn1(vec![0x00, 0x80, 0x03])),
            checksum: ExplicitContextTag1::from(OctetStringAsn1(gss_cksum)),
        }))),
        cusec: ExplicitContextTag4::from(IntegerAsn1(vec![0])),
        ctime: ExplicitContextTag5::from(now_kerberos_time()),
        subkey: Optional::from(Some(ExplicitContextTag6::from(EncryptionKey {
            key_type: ExplicitContextTag0::from(IntegerAsn1(vec![17])),
            key_value: ExplicitContextTag1::from(OctetStringAsn1(subkey.to_vec())),
        }))),
        seq_number: Optional::from(None),
        authorization_data: Optional::from(None),
    });
    let auth_der = picky_asn1_der::to_vec(&authenticator).map_err(|e| anyhow!("authenticator: {e}"))?;
    let enc_auth = enc_session(&st.session_key, 11, &auth_der)?;

    let ap_req = ApReq::from(ApReqInner {
        pvno: ExplicitContextTag0::from(IntegerAsn1(vec![5])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1(vec![AP_REQ_MSG_TYPE])),
        ap_options: ExplicitContextTag2::from(BitStringAsn1::from(BitString::with_bytes(vec![0, 0, 0, 0]))),
        ticket: ExplicitContextTag3::from(st.ticket.clone()),
        authenticator: ExplicitContextTag4::from(encrypted_data(session_etype(&st.session_key), enc_auth)),
    });
    let ap_der = picky_asn1_der::to_vec(&ap_req).map_err(|e| anyhow!("AP-REQ: {e}"))?;
    Ok((super::gss::spnego_krb5_init(&ap_der), subkey))
}