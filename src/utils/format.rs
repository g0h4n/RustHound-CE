/// Fonction to parse DOMAIN.LOCAL to DC=DOMAIN,DC=LOCAL
pub fn domain_to_dc(domain: &str) -> String {
    let split = domain.split('.');
    let mut dc = String::new();
    
    for (i, s) in split.enumerate() {
        dc.push_str("DC=");
        dc.push_str(s);

        if i < domain.split('.').count() - 1 {
            dc.push_str(",");
        }
    }
    dc
}

/// Parse a hash string into the 16-byte NT hash for pass-the-hash.
///
/// Accepts "LMHASH:NTHASH", ":NTHASH" or a bare 32-hex "NTHASH". Returns None
/// when absent or malformed (caller then falls back to password auth).
pub fn parse_hash(h: Option<&str>) -> Option<[u8; 16]> {
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