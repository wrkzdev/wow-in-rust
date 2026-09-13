//! TLS on the RPC port, against the real binary (`specs/11` §1.2).
//!
//! Each test talks to a daemon started for it, with a rustls client that
//! records the certificate the daemon presents -- so what is checked is what
//! a wallet connecting over HTTPS would see.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use wow_storage::db::BlockchainDb;
use wow_storage::env::OpenMode;
use wow_storage::lmdb::LmdbDb;
use wow_types::{Block, Network};

/// The daemon's own provider, so the client here is as pure Rust as it is.
#[path = "../src/rpc/tls/provider.rs"]
#[allow(dead_code)]
mod provider;

struct Scratch(PathBuf);

impl Scratch {
    /// A genesis-only mainnet store.
    fn new(tag: &str) -> Scratch {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p =
            std::env::temp_dir().join(format!("wownerod-tlstest-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        let dir = wow_storage::env::db_dir(&p, Network::Mainnet, false);
        let db = LmdbDb::open_with_map_size(&dir, OpenMode::default(), 2, 32 << 20).unwrap();
        let blob = wow_consensus::genesis::genesis_blob(Network::Mainnet);
        let blk = Block::from_blob(&blob).unwrap();
        let record = wow_consensus::genesis::genesis_record(Network::Mainnet);
        db.add_block(
            &blk,
            &blob,
            record.weight,
            record.long_term_weight,
            record.cumulative_difficulty,
            record.already_generated_coins,
            &[],
        )
        .unwrap();
        Scratch(p)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn start(data_dir: &Path, port: u16, extra: &[&str]) -> Daemon {
    let mut d = Daemon(
        Command::new(env!("CARGO_BIN_EXE_wownerod"))
            .args([
                "--data-dir",
                data_dir.to_str().unwrap(),
                "--serve",
                "--no-zmq",
                "--db-readonly",
                "--non-interactive",
                "--rpc-bind-port",
                &port.to_string(),
            ])
            .args(extra)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start wownerod"),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return d;
        }
        if let Some(status) = d.0.try_wait().unwrap() {
            panic!("wownerod exited early: {status}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("wownerod did not start listening");
}

const REQUEST: &[u8] = b"POST /get_height HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}";

/// A plain request, returning what came back -- nothing, on a TLS-only port.
fn plain(port: u16) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let _ = s.write_all(REQUEST);
    let mut raw = Vec::new();
    let _ = s.read_to_end(&mut raw);
    String::from_utf8_lossy(&raw).into_owned()
}

/// Accepts any server certificate and keeps it.
#[derive(Debug)]
struct Keep {
    seen: Arc<Mutex<Vec<u8>>>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for Keep {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        *self.seen.lock().unwrap() = end_entity.to_vec();
        Ok(ServerCertVerified::assertion())
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

type ClientAuth = (CertificateDer<'static>, PrivateKeyDer<'static>);

/// A request over TLS: the response and the certificate the server showed.
fn over_tls(port: u16, client: Option<ClientAuth>) -> Result<(String, Vec<u8>), String> {
    let provider = Arc::new(provider::provider());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let keep = Arc::new(Keep {
        seen: seen.clone(),
        algorithms: provider.signature_verification_algorithms,
    });
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(keep);
    let config = match client {
        Some((cert, key)) => builder
            .with_client_auth_cert(vec![cert], key)
            .map_err(|e| e.to_string())?,
        None => builder.with_no_client_auth(),
    };
    let tcp = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let conn = rustls::ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap())
        .map_err(|e| e.to_string())?;
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    tls.write_all(REQUEST).map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    if let Err(e) = tls.read_to_end(&mut raw) {
        if raw.is_empty() {
            return Err(e.to_string());
        }
    }
    let cert = seen.lock().unwrap().clone();
    Ok((String::from_utf8_lossy(&raw).into_owned(), cert))
}

fn certificate_in(path: &Path) -> Vec<u8> {
    CertificateDer::from_pem_file(path).unwrap().to_vec()
}

/// A self-signed ECDSA P-256 pair for `localhost`, as PEM files in `dir`.
fn make_pair(dir: &Path, name: &str) -> (PathBuf, PathBuf, ClientAuth) {
    let (key, key_pem) = provider::generate_p256().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    // rcgen without a crypto backend of its own draws no serial number.
    params.serial_number = Some(rcgen::SerialNumber::from(rand_core::RngCore::next_u64(
        &mut rand_core::OsRng,
    )));
    let cert = params
        .self_signed(&provider::CertSigner::new(&key).unwrap())
        .unwrap();
    let crt = dir.join(format!("{name}.crt"));
    let pem = dir.join(format!("{name}.key"));
    std::fs::write(&crt, cert.pem()).unwrap();
    std::fs::write(&pem, &key_pem).unwrap();
    (crt, pem, (cert.der().clone(), key))
}

fn fingerprint_hex(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// **The default.** One port answers plain HTTP and HTTPS; the certificate it
/// presents is the one kept in the data directory, and a restart presents it
/// again.
#[test]
fn autodetect_serves_plain_and_tls_with_a_kept_certificate() {
    let s = Scratch::new("auto");
    let port = free_port();
    let d = start(&s.0, port, &[]);

    assert!(
        plain(port).contains("\"height\":1"),
        "plain HTTP still works"
    );
    let (body, cert) = over_tls(port, None).expect("a TLS request");
    assert!(body.starts_with("HTTP/1.1 200"), "{body}");
    assert!(body.contains("\"height\":1"), "{body}");
    assert_eq!(cert, certificate_in(&s.0.join("rpc_ssl.crt")));

    drop(d);
    let port = free_port();
    let _d = start(&s.0, port, &[]);
    let (_, again) = over_tls(port, None).unwrap();
    assert_eq!(again, cert, "the same certificate after a restart");
}

/// `--rpc-ssl enabled`: TLS only; a plain request gets no HTTP answer.
#[test]
fn enabled_takes_tls_only() {
    let s = Scratch::new("enabled");
    let port = free_port();
    let _d = start(&s.0, port, &["--rpc-ssl", "enabled"]);
    assert!(!plain(port).starts_with("HTTP/"), "no plain answer");
    let (body, _) = over_tls(port, None).unwrap();
    assert!(body.contains("\"height\":1"), "{body}");
}

/// `--rpc-ssl disabled`: plain only, and no certificate made.
#[test]
fn disabled_takes_plain_only() {
    let s = Scratch::new("disabled");
    let port = free_port();
    let _d = start(&s.0, port, &["--rpc-ssl", "disabled"]);
    assert!(plain(port).contains("\"height\":1"));
    assert!(over_tls(port, None).is_err(), "no TLS handshake");
    assert!(!s.0.join("rpc_ssl.crt").exists());
}

/// A certificate given on the command line is the one served.
#[test]
fn a_given_certificate_is_served() {
    let s = Scratch::new("given");
    let (crt, key, _) = make_pair(&s.0, "node");
    let port = free_port();
    let _d = start(
        &s.0,
        port,
        &[
            "--rpc-ssl-certificate",
            crt.to_str().unwrap(),
            "--rpc-ssl-private-key",
            key.to_str().unwrap(),
        ],
    );
    let (_, cert) = over_tls(port, None).unwrap();
    assert_eq!(cert, certificate_in(&crt));
    assert!(!s.0.join("rpc_ssl.crt").exists(), "nothing generated");
}

/// **A pair the C++ left in the data directory**: an RSA key as PKCS#8 PEM
/// and a serial-1, empty-subject certificate. It is served as it is -- the
/// same certificate, so the same fingerprint -- and not replaced.
#[test]
fn an_rsa_pair_left_by_the_cpp_is_served_as_it_is() {
    let s = Scratch::new("cpp-rsa");
    let rsa = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
    let key_pem = rsa.to_pkcs8_pem(LineEnding::LF).unwrap();
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.serial_number = Some(rcgen::SerialNumber::from(1u64));
    let cert = params
        .self_signed(&provider::CertSigner::new(&key).unwrap())
        .unwrap();
    std::fs::write(s.0.join("rpc_ssl.crt"), cert.pem()).unwrap();
    std::fs::write(s.0.join("rpc_ssl.key"), key_pem.as_bytes()).unwrap();

    let port = free_port();
    let _d = start(&s.0, port, &[]);
    let (body, served) = over_tls(port, None).expect("a TLS request");
    assert!(body.contains("\"height\":1"), "{body}");
    assert_eq!(served, cert.der().to_vec());
    assert_eq!(
        fingerprint_hex(&served),
        fingerprint_hex(&certificate_in(&s.0.join("rpc_ssl.crt")))
    );
}

/// **Client certificates.** With a fingerprint listed, TLS is mandatory and
/// only the client holding that certificate gets an answer.
#[test]
fn only_a_listed_client_certificate_gets_in() {
    let s = Scratch::new("clients");
    let (_, _, allowed) = make_pair(&s.0, "allowed");
    let (_, _, other) = make_pair(&s.0, "other");
    let port = free_port();
    let _d = start(
        &s.0,
        port,
        &[
            "--rpc-ssl-allowed-fingerprints",
            &fingerprint_hex(&allowed.0),
        ],
    );

    assert!(!plain(port).starts_with("HTTP/"), "TLS is mandatory");
    assert!(over_tls(port, None).is_err(), "no client certificate");
    assert!(over_tls(port, Some(other)).is_err(), "the wrong one");
    let (body, _) = over_tls(port, Some(allowed)).expect("the listed one");
    assert!(body.contains("\"height\":1"), "{body}");
}
