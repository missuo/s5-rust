//! SOCKS5 over TLS, as Surge's `socks5-tls` policy speaks it: a TLS session
//! is established first and plain SOCKS5 runs inside it.
//!
//! Either bring a certificate (Let's Encrypt or otherwise) or let the server
//! make a self-signed one on first start. A self-signed certificate is kept on
//! disk so its fingerprint stays stable across restarts, since that
//! fingerprint is what clients pin (`server-cert-fingerprint-sha256` in
//! Surge). SIGHUP reloads the files, so a renewed certificate is picked up
//! without dropping connections.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use ring::digest::{digest, SHA256};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use tracing::info;

/// Subject name of a generated certificate. Clients pin the fingerprint, so
/// the name is never checked against anything; it only labels the file.
const SELF_SIGNED_NAME: &str = "s5-rust";

pub struct Tls {
    cert_path: PathBuf,
    key_path: PathBuf,
    acceptor: RwLock<TlsAcceptor>,
}

impl Tls {
    /// Loads the pair at the given paths, generating a self-signed pair there
    /// first when neither file exists. Returns the SHA-256 fingerprint of the
    /// leaf certificate.
    pub fn load_or_generate(cert_path: &Path, key_path: &Path) -> io::Result<(Arc<Self>, String)> {
        match (cert_path.exists(), key_path.exists()) {
            (false, false) => generate(cert_path, key_path)?,
            (true, true) => {}
            // One without the other is a half-finished setup or a typo in one
            // path. Generating would silently overwrite the half that exists.
            _ => {
                return Err(io::Error::other(format!(
                    "only one of {} and {} exists; give both or neither",
                    cert_path.display(),
                    key_path.display()
                )))
            }
        }
        let (acceptor, fingerprint) = build(cert_path, key_path)?;
        let tls = Arc::new(Self {
            cert_path: cert_path.to_path_buf(),
            key_path: key_path.to_path_buf(),
            acceptor: RwLock::new(acceptor),
        });
        Ok((tls, fingerprint))
    }

    pub fn acceptor(&self) -> TlsAcceptor {
        self.acceptor.read().expect("tls lock poisoned").clone()
    }

    /// Re-reads both files. On any error the old certificate stays in use, so
    /// a renewal that wrote a bad file does not take the server down.
    pub fn reload(&self) -> io::Result<String> {
        let (acceptor, fingerprint) = build(&self.cert_path, &self.key_path)?;
        *self.acceptor.write().expect("tls lock poisoned") = acceptor;
        Ok(fingerprint)
    }
}

fn build(cert_path: &Path, key_path: &Path) -> io::Result<(TlsAcceptor, String)> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
        .map_err(|e| io::Error::other(format!("{}: {e}", cert_path.display())))?
        .collect::<Result<_, _>>()
        .map_err(|e| io::Error::other(format!("{}: {e}", cert_path.display())))?;
    let leaf = certs
        .first()
        .ok_or_else(|| io::Error::other(format!("{}: no certificate", cert_path.display())))?;
    let fingerprint = hex::encode(digest(&SHA256, leaf.as_ref()));
    let key = PrivateKeyDer::from_pem_file(key_path)
        .map_err(|e| io::Error::other(format!("{}: {e}", key_path.display())))?;

    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| io::Error::other(format!("certificate and key do not match: {e}")))?;

    Ok((TlsAcceptor::from(Arc::new(config)), fingerprint))
}

fn generate(cert_path: &Path, key_path: &Path) -> io::Result<()> {
    let generated = rcgen::generate_simple_self_signed(vec![SELF_SIGNED_NAME.to_string()])
        .map_err(io::Error::other)?;
    for path in [cert_path, key_path] {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            fs::create_dir_all(dir)?;
        }
    }
    write_private(key_path, generated.signing_key.serialize_pem().as_bytes())?;
    fs::write(cert_path, generated.cert.pem())?;
    info!(
        "Generated self-signed certificate at {} (key {})",
        cert_path.display(),
        key_path.display()
    );
    Ok(())
}

/// Writes the key readable by its owner only, from the moment it exists:
/// creating it with the default mode and narrowing it afterwards would leave
/// a window where any local user could read it.
fn write_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(contents)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_once_and_keeps_the_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("sub/cert.pem");
        let key = dir.path().join("sub/key.pem");
        let (_, fp1) = Tls::load_or_generate(&cert, &key).unwrap();
        assert_eq!(fp1.len(), 64);
        assert!(fp1.chars().all(|c| c.is_ascii_hexdigit()));
        let (tls, fp2) = Tls::load_or_generate(&cert, &key).unwrap();
        assert_eq!(fp1, fp2, "second start must reuse the stored pair");
        assert_eq!(tls.reload().unwrap(), fp1);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&key).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn refuses_half_a_pair() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        fs::write(&cert, "x").unwrap();
        assert!(Tls::load_or_generate(&cert, &key).is_err());
        assert!(!key.exists(), "must not create the missing half");
    }

    #[test]
    fn bad_reload_keeps_the_old_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        let (tls, _) = Tls::load_or_generate(&cert, &key).unwrap();
        fs::write(&cert, "garbage").unwrap();
        assert!(tls.reload().is_err());
        // Still serving: the acceptor from before is in place.
        let _ = tls.acceptor();
    }

    #[test]
    fn mismatched_key_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let (c1, k1) = (dir.path().join("a.pem"), dir.path().join("a.key"));
        let (c2, k2) = (dir.path().join("b.pem"), dir.path().join("b.key"));
        Tls::load_or_generate(&c1, &k1).unwrap();
        Tls::load_or_generate(&c2, &k2).unwrap();
        let err = match Tls::load_or_generate(&c1, &k2) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("mismatched pair accepted"),
        };
        assert!(err.contains("do not match"), "{err}");
    }
}
