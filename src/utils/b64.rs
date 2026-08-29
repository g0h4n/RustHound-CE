//! Base64 encode/decode helpers, standard RFC 4648 alphabet, no external dependency.
//!
//! Used by the ESC8 scanner to encode the NTLM Negotiate token and decode
//! the server's NTLM Challenge from HTTP response headers.

/// Encode `input` to standard Base64 (RFC 4648, with `=` padding).
pub fn b64_encode(input: &[u8]) -> String {
    const TABLE: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = if chunk.len() > 1 { chunk[1] as usize } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as usize } else { 0 };

        out.push(TABLE[(b0 >> 2) & 0x3f] as char);
        out.push(TABLE[((b0 << 4) | (b1 >> 4)) & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((b1 << 2) | (b2 >> 6)) & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[b2 & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

/// Decode standard Base64 (RFC 4648). Returns `None` on invalid input.
pub fn b64_decode(input: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    // Strip padding and whitespace before processing
    let bytes: Vec<u8> = input
        .bytes()
        .filter(|&b| b != b'=' && b != b'\r' && b != b'\n' && b != b' ')
        .collect();

    if bytes.len() % 4 == 1 {
        return None; // impossible valid length
    }

    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut i = 0;
    while i + 1 < bytes.len() {
        let v0 = val(bytes[i])?;
        let v1 = val(bytes[i + 1])?;
        out.push((v0 << 2) | (v1 >> 4));
        if i + 2 < bytes.len() {
            let v2 = val(bytes[i + 2])?;
            out.push((v1 << 4) | (v2 >> 2));
            if i + 3 < bytes.len() {
                let v3 = val(bytes[i + 3])?;
                out.push((v2 << 6) | v3);
            }
        }
        i += 4;
    }
    Some(out)
}

// Tests 

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        // Official RFC 4648 §10 test vectors
        assert_eq!(b64_encode(b""),       "");
        assert_eq!(b64_encode(b"f"),      "Zg==");
        assert_eq!(b64_encode(b"fo"),     "Zm8=");
        assert_eq!(b64_encode(b"foo"),    "Zm9v");
        assert_eq!(b64_encode(b"foob"),   "Zm9vYg==");
        assert_eq!(b64_encode(b"fooba"),  "Zm9vYmE=");
        assert_eq!(b64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn decode_rfc4648_vectors() {
        assert_eq!(b64_decode(""),         Some(b"".to_vec()));
        assert_eq!(b64_decode("Zg=="),     Some(b"f".to_vec()));
        assert_eq!(b64_decode("Zm8="),     Some(b"fo".to_vec()));
        assert_eq!(b64_decode("Zm9v"),     Some(b"foo".to_vec()));
        assert_eq!(b64_decode("Zm9vYg=="), Some(b"foob".to_vec()));
        assert_eq!(b64_decode("Zm9vYmE="), Some(b"fooba".to_vec()));
        assert_eq!(b64_decode("Zm9vYmFy"), Some(b"foobar".to_vec()));
    }

    #[test]
    fn roundtrip_arbitrary_bytes() {
        let data: Vec<u8> = (0u8..=255).collect();
        let encoded = b64_encode(&data);
        let decoded = b64_decode(&encoded).expect("roundtrip decode failed");
        assert_eq!(data, decoded);
    }

    #[test]
    fn decode_without_padding() {
        // Padding is optional on input
        assert_eq!(b64_decode("Zg"),   Some(b"f".to_vec()));
        assert_eq!(b64_decode("Zm8"),  Some(b"fo".to_vec()));
    }

    #[test]
    fn decode_invalid_char_returns_none() {
        assert_eq!(b64_decode("TQ!Q"), None);
        assert_eq!(b64_decode("TQ@Q"), None);
    }

    #[test]
    fn decode_impossible_length_returns_none() {
        // Length 1 mod 4 is never valid Base64
        assert_eq!(b64_decode("A"), None);
    }

    #[test]
    fn decode_ignores_whitespace_and_padding() {
        // Common in PEM / HTTP headers
        assert_eq!(b64_decode("Zm9v\r\nYmFy"), Some(b"foobar".to_vec()));
        assert_eq!(b64_decode("Zm9vYmFy=="), Some(b"foobar".to_vec()));
    }
}