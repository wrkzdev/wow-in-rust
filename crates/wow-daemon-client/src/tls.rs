//! TLS to a daemon, for an `https://` address (`specs/11` §1.2).
//!
//! On the node's own provider (`wow-tls`): pure Rust, no ring, aws-lc-rs or
//! OpenSSL. The certificate is checked against the Mozilla roots
//! (`webpki-roots`), for the host's name, as a browser checks it — unless the
//! endpoint accepts any, which a node serving the self-signed certificate
//! `wownerod` makes needs, as the C++'s `--daemon-ssl-allow-any-cert` does.

use std::net::TcpStream;
use std::sync::{Arc, OnceLock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
    StreamOwned,
};

use crate::http::{Certificates, HttpError};

/// A TLS connection over a socket.
pub type Stream = StreamOwned<ClientConnection, TcpStream>;

/// Start TLS over `tcp` to `host`: a name, or an address without brackets.
/// The handshake happens on the first write.
pub fn connect(
    tcp: TcpStream,
    host: &str,
    certificates: Certificates,
) -> Result<Stream, HttpError> {
    let name = ServerName::try_from(host.to_string())
        .map_err(|_| HttpError::Tls(format!("`{host}` is not a name a certificate is for")))?;
    let conn = ClientConnection::new(config(certificates)?, name)
        .map_err(|e| HttpError::Tls(e.to_string()))?;
    Ok(StreamOwned::new(conn, tcp))
}

/// What a failed read or write was, when TLS failed it. rustls reports its
/// errors inside an I/O error, which alone would say only "invalid data".
pub fn describe(e: &std::io::Error) -> Option<String> {
    let tls = e.get_ref()?.downcast_ref::<rustls::Error>()?;
    Some(match tls {
        rustls::Error::InvalidCertificate(why) => format!(
            "the node's certificate is not trusted ({why:?}). A node with a self-signed \
             certificate can only be used by accepting its certificate as it is"
        ),
        other => other.to_string(),
    })
}

/// One configuration for each way of checking, made the first time it is
/// wanted: loading the roots is not free, and a sync makes a request a batch.
fn config(certificates: Certificates) -> Result<Arc<ClientConfig>, HttpError> {
    static CHECKED: OnceLock<Result<Arc<ClientConfig>, String>> = OnceLock::new();
    static ANY: OnceLock<Result<Arc<ClientConfig>, String>> = OnceLock::new();
    let cell = match certificates {
        Certificates::Checked => &CHECKED,
        Certificates::Any => &ANY,
    };
    cell.get_or_init(|| build(certificates).map(Arc::new))
        .clone()
        .map_err(HttpError::Tls)
}

fn build(certificates: Certificates) -> Result<ClientConfig, String> {
    let provider = Arc::new(wow_tls::provider::provider());
    let algorithms = provider.signature_verification_algorithms;
    // TLS 1.3 and 1.2, which is what the provider has.
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .map_err(|e| e.to_string())?;
    Ok(match certificates {
        Certificates::Checked => {
            let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            builder.with_root_certificates(roots).with_no_client_auth()
        }
        Certificates::Any => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCertificate { algorithms }))
            .with_no_client_auth(),
    })
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
