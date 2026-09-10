//! Client-certificate TLS configuration for certificate authentication
//! (Pass-the-Certificate / Schannel) over LDAPS.
//!
//! Builds a rustls `ClientConfig` that presents a client certificate, matching
//! the rustls backend ldap3 uses (`tls-rustls-ring`). It is attached to
//! `LdapConnSettings::set_config` when a certificate is provided. AD then maps
//! the certificate to an account at the TLS layer (implicit Schannel mapping),
//! so no explicit bind is performed.
//!
//! Accepts a PFX/PKCS#12 file (`--pfx` / `--pfx-pass`) or a PEM cert + key pair
//! (`--crt` / `--key`). TLS 1.2 is enforced for compatibility with older DCs
//! (some Windows Server 2016 DCs do not answer a TLS 1.3 ClientHello on LDAPS).

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::version::TLS12;
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};

/// Build a rustls `ClientConfig` presenting the given client certificate.
pub fn build_client_config(
    pfx: Option<&str>,
    pfx_pass: Option<&str>,
    crt: Option<&str>,
    key: Option<&str>,
) -> Result<Arc<ClientConfig>> {
    let (certs, key_der) = match (pfx, crt, key) {
        (Some(pfx_path), _, _) => load_pfx(pfx_path, pfx_pass.unwrap_or(""))?,
        (None, Some(crt_path), Some(key_path)) => load_pem(crt_path, key_path)?,
        _ => return Err(anyhow!("certificate auth requires --pfx, or both --crt and --key")),
    };

    // TLS 1.2 only: some Server 2016 DCs do not answer a TLS 1.3 ClientHello on LDAPS.
    let config = ClientConfig::builder_with_protocol_versions(&[&TLS12])
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoServerVerify))
        .with_client_auth_cert(certs, key_der)
        .map_err(|e| anyhow!("client auth cert: {e}"))?;

    Ok(Arc::new(config))
}

/// Load cert chain + private key from a PFX/PKCS#12 file.
fn load_pfx(
    path: &str,
    password: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    use p12_keystore::{KeyStore, KeyStoreEntry, Pkcs12ImportPolicy};

    let data = std::fs::read(path).with_context(|| format!("read pfx {path}"))?;
    let ks = KeyStore::from_pkcs12(&data, password, Pkcs12ImportPolicy::default())
        .map_err(|e| anyhow!("parse pfx (convert to PEM with `openssl pkcs12` if this fails): {e:?}"))?;

    for (_alias, entry) in ks.entries() {
        if let KeyStoreEntry::PrivateKeyChain(chain) = entry {
            let key = PrivateKeyDer::try_from(chain.key().as_der().to_vec())
                .map_err(|e| anyhow!("pfx private key: {e}"))?;
            let certs: Vec<CertificateDer<'static>> = chain
                .certs()
                .iter()
                .map(|c| CertificateDer::from(c.as_der().to_vec()))
                .collect();
            if certs.is_empty() {
                return Err(anyhow!("pfx has a key but no certificate"));
            }
            return Ok((certs, key));
        }
    }
    Err(anyhow!("no private-key entry found in pfx"))
}

/// Load cert chain (crt) + private key (key) from PEM files.
fn load_pem(
    crt: &str,
    key: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let crt_bytes = std::fs::read(crt).with_context(|| format!("read crt {crt}"))?;
    let key_bytes = std::fs::read(key).with_context(|| format!("read key {key}"))?;

    let certs = rustls_pemfile::certs(&mut &crt_bytes[..])
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("parse crt: {e}"))?;
    if certs.is_empty() {
        return Err(anyhow!("no certificate in {crt}"));
    }

    let key_der = rustls_pemfile::private_key(&mut &key_bytes[..])
        .map_err(|e| anyhow!("parse key: {e}"))?
        .ok_or_else(|| anyhow!("no private key in {key}"))?;

    Ok((certs, key_der))
}

/// ServerCertVerifier that accepts everything, consistent with the
/// `set_no_tls_verify(true)` already used by RustHound-CE for LDAPS.
#[derive(Debug)]
struct NoServerVerify;

impl ServerCertVerifier for NoServerVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}