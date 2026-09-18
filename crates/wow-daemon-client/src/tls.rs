//! TLS to a daemon (`specs/11` §1.2), as `epee::net_utils::ssl_options_t`
//! sets it up on the wallet's side.
//!
//! On the node's own provider (`wow-tls`): pure Rust, no ring, aws-lc-rs or
//! OpenSSL. What a node's certificate is checked against is
//! [`Certificates`]':
//!
//! | [`Certificates`] | The C++'s `ssl_verification_t` | Accepted |
//! |---|---|---|
//! | `Checked` | `system_ca` | chains to the Mozilla roots (`webpki-roots`), for the host's name |
//! | `Any` | `none` | anything: `--daemon-ssl-allow-any-cert` |
//! | `Pinned` | `user_certificates` | a listed SHA-256 fingerprint, or a certificate in the CA file |
//! | `Pinned`, chained | `user_ca` | that, or a chain to a certificate in the CA file |
//!
//! No name is checked for a pinned certificate, as the C++ checks none.
//!
//! # Strict and opportunistic
//!
//! A strict connection (`https://`, `--daemon-ssl enabled`) fails when the
//! certificate does not check out. An opportunistic one, what
//! `--daemon-ssl autodetect` makes, accepts it and says whether it did:
//! `configure`'s verify callback does the same under autodetect, logging "SSL
//! peer has not been verified" and keeping the connection encrypted.

use std::net::TcpStream;
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::{
    verify_tls12_signature, verify_tls13_signature, CryptoProvider, WebPkiSupportedAlgorithms,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
    StreamOwned,
};

use crate::http::{Certificates, ClientCertificate, HttpError, Pins};

/// A TLS connection over a socket.
pub type Stream = StreamOwned<ClientConnection, TcpStream>;

/// Start TLS over `tcp` to `host`, a name or an address without brackets, and
/// finish the handshake. Returns the connection and whether the node's
/// certificate checked out.
///
/// The handshake is bounded by `handshake_timeout` rather than the reads'
/// `timeout`: a node that does not speak TLS may wait for the rest of an HTTP
/// request that never comes, and autodetect has to find that out in the time
/// a connection takes, as `try_connect` does.
pub fn connect(
    mut tcp: TcpStream,
    host: &str,
    certificates: &Certificates,
    client_certificate: Option<&ClientCertificate>,
    strict: bool,
    handshake_timeout: Duration,
    timeout: Duration,
) -> Result<(Stream, bool), HttpError> {
    let name = ServerName::try_from(host.to_string())
        .map_err(|_| HttpError::Tls(format!("`{host}` is not a name a certificate is for")))?;
    let checker = verifier(certificates)?;
    let in_handshake = if strict {
        checker.clone()
    } else {
        any_certificate()
    };
    let config = config(in_handshake, certificates, strict, client_certificate)?;
    let mut conn =
        ClientConnection::new(config, name.clone()).map_err(|e| HttpError::Tls(e.to_string()))?;

    tcp.set_read_timeout(Some(handshake_timeout))?;
    tcp.set_write_timeout(Some(handshake_timeout))?;
    while conn.is_handshaking() {
        if conn.complete_io(&mut tcp)? == (0, 0) {
            return Err(HttpError::Tls(
                "the node stopped answering during the TLS handshake".into(),
            ));
        }
    }
    tcp.set_read_timeout(Some(timeout))?;
    tcp.set_write_timeout(Some(timeout))?;

    // `Any` checks nothing, so nothing is verified by it.
    let verified = !matches!(certificates, Certificates::Any)
        && (strict
            || match conn.peer_certificates() {
                Some([end_entity, intermediates @ ..]) => checker
                    .verify_server_cert(end_entity, intermediates, &name, &[], UnixTime::now())
                    .is_ok(),
                _ => false,
            });
    Ok((StreamOwned::new(conn, tcp), verified))
}

/// What a failed read or write was, when TLS failed it. rustls reports its
/// errors inside an I/O error, which alone would say only "invalid data".
pub fn describe(e: &std::io::Error) -> Option<String> {
    let tls = e.get_ref()?.downcast_ref::<rustls::Error>()?;
    Some(match tls {
        rustls::Error::InvalidCertificate(why) => format!(
            "the node's certificate is not trusted ({why:?}). A node with a self-signed \
             certificate can be used by pinning its fingerprint, or by accepting its \
             certificate as it is"
        ),
        other => other.to_string(),
    })
}

/// The certificates in a PEM file, as DER: what `--daemon-ssl-ca-certificates`
/// names.
pub fn read_certificates(path: &Path) -> Result<Vec<Vec<u8>>, String> {
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(|e| format!("cannot read {}: {e:?}", path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{}: {e:?}", path.display()))?;
    if certs.is_empty() {
        return Err(format!("{} holds no certificate", path.display()));
    }
    Ok(certs.into_iter().map(|c| c.as_ref().to_vec()).collect())
}

/// A certificate's SHA-256 fingerprint, the C++'s
/// `X509_digest(cert, EVP_sha256())`, from the provider's own SHA-256.
pub fn fingerprint(der: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    if let Some(suite) = wow_tls::provider::TLS13_AES_128_GCM_SHA256.tls13() {
        let digest = rustls::crypto::hash::Hash::hash(suite.common.hash_provider, der);
        out.copy_from_slice(digest.as_ref());
    }
    out
}

fn provider() -> Arc<CryptoProvider> {
    static PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    PROVIDER
        .get_or_init(|| Arc::new(wow_tls::provider::provider()))
        .clone()
}

/// What checks a certificate as `certificates` says.
///
/// The roots are loaded the first time they are wanted, and once: that is not
/// free, and a connection is made far more often than a wallet starts.
fn verifier(certificates: &Certificates) -> Result<Arc<dyn ServerCertVerifier>, HttpError> {
    match certificates {
        Certificates::Checked => {
            static ROOTS: OnceLock<Result<Arc<WebPkiServerVerifier>, String>> = OnceLock::new();
            let roots = ROOTS
                .get_or_init(|| {
                    let roots =
                        RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                    WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider())
                        .build()
                        .map_err(|e| e.to_string())
                })
                .clone()
                .map_err(HttpError::Tls)?;
            Ok(roots)
        }
        Certificates::Any => Ok(any_certificate()),
        Certificates::Pinned(pins) => Ok(Arc::new(PinnedCertificate::new(pins)?)),
    }
}

fn any_certificate() -> Arc<dyn ServerCertVerifier> {
    Arc::new(AnyCertificate {
        algorithms: provider().signature_verification_algorithms,
    })
}

/// A client configuration that checks with `verifier`.
///
/// The two made most often, the roots strictly and anything at all, with no
/// certificate of this wallet's to show, are made once each.
fn config(
    verifier: Arc<dyn ServerCertVerifier>,
    certificates: &Certificates,
    strict: bool,
    client_certificate: Option<&ClientCertificate>,
) -> Result<Arc<ClientConfig>, HttpError> {
    static CHECKED: OnceLock<Result<Arc<ClientConfig>, String>> = OnceLock::new();
    static ANY: OnceLock<Result<Arc<ClientConfig>, String>> = OnceLock::new();
    let cell = match (certificates, strict, client_certificate) {
        (_, _, Some(_)) => None,
        (Certificates::Checked, true, None) => Some(&CHECKED),
        (Certificates::Pinned(_), true, None) => None,
        (_, _, None) => Some(&ANY),
    };
    match cell {
        Some(cell) => cell
            .get_or_init(|| build(verifier, None).map(Arc::new))
            .clone()
            .map_err(HttpError::Tls),
        None => build(verifier, client_certificate)
            .map(Arc::new)
            .map_err(HttpError::Tls),
    }
}

fn build(
    verifier: Arc<dyn ServerCertVerifier>,
    client_certificate: Option<&ClientCertificate>,
) -> Result<ClientConfig, String> {
    // TLS 1.3 and 1.2, which is what the provider has, and what the C++ allows.
    let builder = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let Some(client) = client_certificate else {
        return Ok(builder.with_no_client_auth());
    };
    let chain = CertificateDer::pem_file_iter(&client.certificate)
        .map_err(|e| format!("cannot read {}: {e:?}", client.certificate.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{}: {e:?}", client.certificate.display()))?;
    let key = PrivateKeyDer::from_pem_file(&client.private_key)
        .map_err(|e| format!("cannot read {}: {e:?}", client.private_key.display()))?;
    builder
        .with_client_auth_cert(chain, key)
        .map_err(|e| format!("the certificate this wallet shows a node: {e}"))
}

/// Accepts whatever certificate the node shows, and still checks that the
/// node holds its key: the connection is encrypted, but who is at the other
/// end is not checked.
#[derive(Debug)]
struct AnyCertificate {
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
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

/// `user_certificates`, and `user_ca` with `allow_chained`: a certificate
/// whose fingerprint is listed or which is itself in the CA file, or with
/// `allow_chained` one that chains to a certificate in it. As `wownerod`
/// checks a client's.
#[derive(Debug)]
struct PinnedCertificate {
    /// Listed fingerprints, and those of the CA file's certificates.
    fingerprints: Vec<[u8; 32]>,
    /// The CA file as roots, with `allow_chained`.
    roots: Option<RootCertStore>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl PinnedCertificate {
    fn new(pins: &Pins) -> Result<PinnedCertificate, HttpError> {
        let mut fingerprints = pins.fingerprints.clone();
        fingerprints.extend(pins.ca.iter().map(|der| fingerprint(der)));
        let roots = if pins.allow_chained {
            let mut roots = RootCertStore::empty();
            for der in &pins.ca {
                roots
                    .add(CertificateDer::from(der.clone()))
                    .map_err(|e| HttpError::Tls(format!("a CA certificate: {e}")))?;
            }
            Some(roots)
        } else {
            None
        };
        Ok(PinnedCertificate {
            fingerprints,
            roots,
            algorithms: provider().signature_verification_algorithms,
        })
    }
}

impl ServerCertVerifier for PinnedCertificate {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if self.fingerprints.contains(&fingerprint(end_entity)) {
            return Ok(ServerCertVerified::assertion());
        }
        if let Some(roots) = &self.roots {
            let cert = rustls::server::ParsedCertificate::try_from(end_entity)?;
            rustls::client::verify_server_cert_signed_by_trust_anchor(
                &cert,
                roots,
                intermediates,
                now,
                self.algorithms.all,
            )?;
            return Ok(ServerCertVerified::assertion());
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA-256 of the DER, the C++'s `X509_digest(cert, EVP_sha256())`:
    /// FIPS 180-2's "abc" vector stands in for a certificate.
    #[test]
    fn a_fingerprint_is_sha256() {
        assert_eq!(
            wow_crypto::hex::encode(&fingerprint(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
