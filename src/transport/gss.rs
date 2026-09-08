//! Minimal GSS-API / SPNEGO framing for a Kerberos AP-REQ carried in an SMB2
//! SESSION_SETUP. Ported from icedracon/adhammer (crates/kerberos/src/gss.rs) <https://github.com/icedracon/adhammer>.

use log::{debug, trace};

fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else {
        let mut b = Vec::new();
        let mut v = n;
        while v > 0 {
            b.insert(0, (v & 0xff) as u8);
            v >>= 8;
        }
        let mut out = vec![0x80 | b.len() as u8];
        out.extend_from_slice(&b);
        out
    }
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&der_len(content.len()));
    out.extend_from_slice(content);
    out
}

const SPNEGO_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
const KRB5_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];

/// Wrap a raw AP-REQ DER as the GSS-Kerberos mechToken
/// ([APPLICATION 0] { krb5-OID, TOK_ID=0x0100, AP-REQ }).
fn gss_krb5_aprep(ap_req_der: &[u8]) -> Vec<u8> {
    trace!("[gss] wrapping AP-REQ ({} bytes) as GSS-Kerberos mechToken", ap_req_der.len());
    let mut inner = Vec::new();
    inner.extend_from_slice(&tlv(0x06, KRB5_OID));
    inner.extend_from_slice(&[0x01, 0x00]); // TOK_ID = AP-REQ
    inner.extend_from_slice(ap_req_der);
    let out = tlv(0x60, &inner);
    trace!("[gss] GSS-Kerberos mechToken = {} bytes", out.len());
    out
}

/// SPNEGO negTokenInit carrying a Kerberos AP-REQ, for an SMB2 SESSION_SETUP.
pub fn spnego_krb5_init(ap_req_der: &[u8]) -> Vec<u8> {
    trace!("[gss] building SPNEGO negTokenInit from AP-REQ ({} bytes)", ap_req_der.len());
    let mech_token = gss_krb5_aprep(ap_req_der);
    let mech_types = tlv(0x30, &tlv(0x06, KRB5_OID));
    let mut neg_init = Vec::new();
    neg_init.extend_from_slice(&tlv(0xa0, &mech_types)); // mechTypes [0]
    neg_init.extend_from_slice(&tlv(0xa2, &tlv(0x04, &mech_token))); // mechToken [2]
    trace!("[gss] negTokenInit body = {} bytes (mechTypes + mechToken)", neg_init.len());
    let neg_token = tlv(0xa0, &tlv(0x30, &neg_init));
    let mut inner = Vec::new();
    inner.extend_from_slice(&tlv(0x06, SPNEGO_OID));
    inner.extend_from_slice(&neg_token);
    let out = tlv(0x60, &inner);
    debug!("[gss] SPNEGO token ready: {} bytes for SMB2 SESSION_SETUP", out.len());
    out
}