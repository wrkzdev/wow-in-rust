//! TLS on the RPC listeners (`specs/11` §1.2), set up the way the C++'s
//! `epee::net_utils::ssl_options_t` sets it up.
//!
//! # Autodetect, the default
//!
//! `--rpc-ssl autodetect` serves plain HTTP and HTTPS on the same port. The
//! first bytes of each connection are looked at, and a TLS ClientHello gets a
//! TLS handshake ([`is_client_hello`], the C++'s `is_ssl`). Plain clients keep
//! working and a client that wants encryption can have it, which is why the
//! C++ makes this the default. `enabled` takes TLS only; `disabled`, plain
//! only.
//!
//! # The certificate
//!
//! Without `--rpc-ssl-certificate`, a self-signed certificate is made at the
//! first start and kept as `rpc_ssl.crt` and `rpc_ssl.key` in the data
//! directory -- the files the C++ writes and reads -- so its fingerprint stays
//! the same across restarts and a client can pin it. The C++ makes RSA-4096;
//! this build makes ECDSA P-256, since `ring` cannot generate RSA keys. Every
//! TLS client accepts either, and a pair the C++ left in the directory is
//! served as it is.
//!
//! # Client certificates
//!
//! Asked for only when `--rpc-ssl-allowed-fingerprints` or
//! `--rpc-ssl-ca-certificates` names what to accept, and either one makes TLS
//! mandatory, as in `do_process_ssl`. A client certificate is accepted when its
//! SHA-256 fingerprint is listed or it is itself in the CA file; with
//! `--rpc-ssl-allow-chained`, also when it chains to a certificate in that
//! file. `--rpc-ssl-allow-any-cert` turns the check off.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::{
    verify_tls12_signature, verify_tls13_signature, CryptoProvider, WebPkiSupportedAlgorithms,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{NoServerSessionStorage, WebPkiClientVerifier};
use rustls::{
    DigitallySignedStruct, DistinguishedName, RootCertStore, ServerConfig, ServerConnection,
    SignatureScheme, StreamOwned,
};

use super::http;
use crate::cli::{Config, RpcSsl};

const LOG: &str = "daemon.rpc";

/// The name the C++ keeps its generated certificate under, in the data
/// directory, with `.crt` and `.key` appended.
pub const CERT_BASENAME: &str = "rpc_ssl";

/// `get_ssl_magic_size()`: the bytes [`is_client_hello`] looks at.
const MAGIC_SIZE: usize = 9;

/// Half a year, as the C++ makes them.
const GENERATED_VALIDITY: Duration = Duration::from_secs(3_600 * 24 * 182);

/// `is_ssl`: whether a connection's first bytes are a TLS ClientHello -- a
/// handshake record, version 3, a ClientHello message whose length agrees with
/// the record's.
pub fn is_client_hello(data: &[u8]) -> bool {
    data.len() >= MAGIC_SIZE
        && data[0] == 0x16
        && data[1] == 3
        && data[5] == 1
        && data[6] == 0
        && usize::from(data[3]) * 256 + usize::from(data[4])
            == usize::from(data[7]) * 256 + usize::from(data[8]) + 4
}

/// A certificate's SHA-256 fingerprint.
pub fn fingerprint(der: &[u8]) -> [u8; 32] {
    ring::digest::digest(&ring::digest::SHA256, der)
        .as_ref()
        .try_into()
        .unwrap_or([0; 32])
}

/// `aa:bb:...`, as fingerprints are usually shown.
pub fn fingerprint_hex(fp: &[u8; 32]) -> String {
    fp.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// A fingerprint as `--rpc-ssl-allowed-fingerprints` takes it: hex, with
/// spaces and colons ignored (`from_hex_locale`).
pub fn parse_fingerprint(text: &str) -> Result<[u8; 32], String> {
    let hex: String = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect::<String>()
        .to_ascii_lowercase();
    let bytes = wow_crypto::hex::decode(&hex).ok_or_else(|| format!("`{text}` is not hex"))?;
    bytes
        .try_into()
        .map_err(|_| "a SHA-256 fingerprint should be 32 bytes long".to_string())
}

type Pair = (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>);

/// A PEM certificate chain and its private key.
pub fn load_pair(cert: &Path, key: &Path) -> Result<Pair, String> {
    let certs = CertificateDer::pem_file_iter(cert)
        .map_err(|e| format!("cannot read the certificate {}: {e:?}", cert.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{}: {e:?}", cert.display()))?;
    if certs.is_empty() {
        return Err(format!("{} holds no certificate", cert.display()));
    }
    let key = PrivateKeyDer::from_pem_file(key)
        .map_err(|e| format!("cannot read the private key {}: {e:?}", key.display()))?;
    Ok((certs, key))
}

/// A self-signed certificate and its key, as PEM: serial 1, an empty subject,
/// valid from now for half a year, as the C++ makes them.
fn generate() -> Result<(String, String), String> {
    let key = rcgen::KeyPair::generate().map_err(|e| format!("cannot generate a TLS key: {e}"))?;
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.serial_number = Some(rcgen::SerialNumber::from(1u64));
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + GENERATED_VALIDITY;
    let cert = params
        .self_signed(&key)
        .map_err(|e| format!("cannot make a TLS certificate: {e}"))?;
    Ok((cert.pem(), key.serialize_pem()))
}

/// The pair kept in `dir`, made and written there first when there is none.
fn stored_or_generated(dir: &Path) -> Result<Pair, String> {
    let crt = dir.join(format!("{CERT_BASENAME}.crt"));
    let key = dir.join(format!("{CERT_BASENAME}.key"));
    match (crt.exists(), key.exists()) {
        (true, true) => return load_pair(&crt, &key),
        (false, false) => {}
        // The C++'s own warning: a `.key` is often left behind when a `.crt`
        // is copied, and serving a fresh pair would silently change the
        // fingerprint clients pinned.
        _ => {
            return Err(format!(
                "{} and {} must both exist or both not exist",
                crt.display(),
                key.display()
            ))
        }
    }
    let (cert_pem, key_pem) = generate()?;
    write_private(&key, key_pem.as_bytes())
        .map_err(|e| format!("cannot write {}: {e}", key.display()))?;
    std::fs::write(&crt, cert_pem.as_bytes())
        .map_err(|e| format!("cannot write {}: {e}", crt.display()))?;
    wow_log::info!(
        LOG,
        "generated a TLS certificate for the RPC server in {}",
        crt.display()
    );
    load_pair(&crt, &key)
}

/// Write a private key readable by its owner only, as the C++ leaves it.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o400);
    }
    options.open(path)?.write_all(bytes)
}

/// The client-certificate check, when there is one to make.
#[derive(Debug)]
struct ClientCheck {
    /// Listed fingerprints, and those of the CA file's certificates.
    fingerprints: Vec<[u8; 32]>,
    /// With `--rpc-ssl-allow-chained`: a chain to the CA file will do.
    chained: Option<Arc<dyn ClientCertVerifier>>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ClientCheck {
    fn new(cfg: &Config, provider: &Arc<CryptoProvider>) -> Result<ClientCheck, String> {
        let mut fingerprints = cfg.rpc_ssl_allowed_fingerprints.clone();
        let mut chained = None;
        if let Some(path) = &cfg.rpc_ssl_ca_certificates {
            let certs = CertificateDer::pem_file_iter(path)
                .map_err(|e| format!("cannot read {}: {e:?}", path.display()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("{}: {e:?}", path.display()))?;
            if certs.is_empty() {
                return Err(format!("{} holds no certificate", path.display()));
            }
            fingerprints.extend(certs.iter().map(|c| fingerprint(c)));
            if cfg.rpc_ssl_allow_chained {
                let mut roots = RootCertStore::empty();
                for c in certs {
                    roots
                        .add(c)
                        .map_err(|e| format!("{}: {e}", path.display()))?;
                }
                chained = Some(
                    WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                        .build()
                        .map_err(|e| format!("{}: {e}", path.display()))?,
                );
            }
        }
        Ok(ClientCheck {
            fingerprints,
            chained,
            algorithms: provider.signature_verification_algorithms,
        })
    }
}

impl ClientCertVerifier for ClientCheck {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        if self.fingerprints.contains(&fingerprint(end_entity)) {
            return Ok(ClientCertVerified::assertion());
        }
        if let Some(v) = &self.chained {
            return v.verify_client_cert(end_entity, intermediates, now);
        }
        wow_log::warn!(
            LOG,
            "a client certificate is not in the allowed list; connection dropped"
        );
        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnknownIssuer,
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// A connection, plain or TLS.
pub enum Stream {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ServerConnection, TcpStream>>),
}

impl Stream {
    /// End the conversation: a TLS connection says so (`close_notify`) before
    /// the socket closes, so the client can tell a whole answer from a cut one.
    pub fn finish(&mut self) {
        if let Stream::Tls(s) = self {
            s.conn.send_close_notify();
            let _ = s.flush();
        }
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read(buf),
            Stream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Stream::Plain(s) => s.write(buf),
            Stream::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Stream::Plain(s) => s.flush(),
            Stream::Tls(s) => s.flush(),
        }
    }
}

/// The RPC server's TLS.
pub struct Tls {
    /// `Enabled` or `Autodetect`; with `Disabled` there is no `Tls`.
    support: RpcSsl,
    config: Arc<ServerConfig>,
    fingerprint: [u8; 32],
}

impl Tls {
    /// From the options, or `None` when TLS is off. `data_dir` is where a
    /// generated certificate is kept.
    pub fn from_config(cfg: &Config, data_dir: &Path) -> Result<Option<Tls>, String> {
        let verify = !cfg.rpc_ssl_allow_any_cert
            && (!cfg.rpc_ssl_allowed_fingerprints.is_empty()
                || cfg.rpc_ssl_ca_certificates.is_some());
        // Naming acceptable client certificates implies TLS, whatever
        // `--rpc-ssl` says (`do_process_ssl`).
        let support = if verify { RpcSsl::Enabled } else { cfg.rpc_ssl };
        if support == RpcSsl::Disabled {
            return Ok(None);
        }

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let (certs, key) = match (&cfg.rpc_ssl_certificate, &cfg.rpc_ssl_private_key) {
            (Some(cert), Some(key)) => load_pair(cert, key)?,
            _ => stored_or_generated(data_dir)?,
        };
        let fingerprint = fingerprint(&certs[0]);

        // TLS 1.2 and up, as the C++ allows; rustls offers nothing older, and
        // only AEAD suites.
        let builder = ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|e| format!("TLS: {e}"))?;
        let builder = if verify {
            builder.with_client_cert_verifier(Arc::new(ClientCheck::new(cfg, &provider)?))
        } else {
            builder.with_no_client_auth()
        };
        let mut config = builder
            .with_single_cert(certs, key)
            .map_err(|e| format!("TLS: the certificate and the private key do not match: {e}"))?;
        // `SSL_SESS_CACHE_OFF`: no session resumption.
        config.session_storage = Arc::new(NoServerSessionStorage {});

        Ok(Some(Tls {
            support,
            config: Arc::new(config),
            fingerprint,
        }))
    }

    /// The served certificate's SHA-256 fingerprint.
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// TLS only, rather than autodetected.
    pub fn is_required(&self) -> bool {
        self.support == RpcSsl::Enabled
    }

    /// Wrap an accepted connection whose timeouts are set: TLS when required,
    /// or when autodetect finds a ClientHello at the front of it.
    pub fn accept(&self, tcp: TcpStream) -> std::io::Result<Stream> {
        if self.support == RpcSsl::Autodetect && !starts_with_client_hello(&tcp)? {
            return Ok(Stream::Plain(tcp));
        }
        let conn = ServerConnection::new(self.config.clone()).map_err(std::io::Error::other)?;
        Ok(Stream::Tls(Box::new(StreamOwned::new(conn, tcp))))
    }
}

/// Peek at a connection's first bytes. A plain request is known by its first
/// byte; a ClientHello needs [`MAGIC_SIZE`] of them, which may arrive in more
/// than one packet.
fn starts_with_client_hello(tcp: &TcpStream) -> std::io::Result<bool> {
    let mut buf = [0u8; MAGIC_SIZE];
    let deadline = Instant::now() + http::READ_TIMEOUT;
    loop {
        let n = tcp.peek(&mut buf)?;
        if n == 0 || buf[0] != 0x16 || n >= MAGIC_SIZE {
            return Ok(is_client_hello(&buf[..n]));
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!("wownerod-tls-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// A real ClientHello is recognised, and an HTTP request is not.
    #[test]
    fn a_client_hello_is_told_from_a_plain_request() {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(rustls::DEFAULT_VERSIONS)
            .unwrap()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        let mut client =
            rustls::ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap())
                .unwrap();
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();

        assert!(is_client_hello(&hello));
        assert!(!is_client_hello(b"POST /json_rpc HTTP/1.1\r\n"));
        assert!(
            !is_client_hello(&hello[..MAGIC_SIZE - 1]),
            "too short to tell"
        );
        let mut wrong_length = hello.clone();
        wrong_length[4] ^= 1;
        assert!(!is_client_hello(&wrong_length));
    }

    #[test]
    fn fingerprints_parse_with_or_without_separators() {
        let fp = [0xabu8; 32];
        let colons = fingerprint_hex(&fp);
        assert_eq!(parse_fingerprint(&colons).unwrap(), fp);
        assert_eq!(parse_fingerprint(&"AB ".repeat(32)).unwrap(), fp);
        assert!(parse_fingerprint("abcd").unwrap_err().contains("32 bytes"));
        assert!(parse_fingerprint("zz").unwrap_err().contains("not hex"));
    }

    /// **The kept certificate.** Made once and served again after a restart,
    /// so a pinned fingerprint holds; half of a pair is refused rather than
    /// quietly replaced.
    #[test]
    fn the_generated_certificate_is_kept_and_reused() {
        let dir = scratch("keep");
        let cfg = Config::default();
        let first = Tls::from_config(&cfg, &dir)
            .unwrap()
            .expect("autodetect is on");
        assert!(!first.is_required());
        assert!(dir.join("rpc_ssl.crt").exists() && dir.join("rpc_ssl.key").exists());

        let again = Tls::from_config(&cfg, &dir).unwrap().unwrap();
        assert_eq!(
            again.fingerprint(),
            first.fingerprint(),
            "the same certificate"
        );

        std::fs::remove_file(dir.join("rpc_ssl.crt")).unwrap();
        let e = Tls::from_config(&cfg, &dir).err().unwrap();
        assert!(e.contains("both exist or both not exist"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `disabled` is no TLS, unless client certificates are named, which
    /// makes it mandatory.
    #[test]
    fn naming_client_certificates_makes_tls_mandatory() {
        let dir = scratch("modes");
        let mut cfg = Config {
            rpc_ssl: RpcSsl::Disabled,
            ..Config::default()
        };
        assert!(Tls::from_config(&cfg, &dir).unwrap().is_none());
        assert!(
            !dir.join("rpc_ssl.crt").exists(),
            "nothing made when TLS is off"
        );

        cfg.rpc_ssl_allowed_fingerprints = vec![[1; 32]];
        assert!(Tls::from_config(&cfg, &dir).unwrap().unwrap().is_required());

        cfg.rpc_ssl_allow_any_cert = true;
        assert!(
            Tls::from_config(&cfg, &dir).unwrap().is_none(),
            "no check to make, so --rpc-ssl stands"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
