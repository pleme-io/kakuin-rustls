//! kakuin-rustls — bridge SPIFFE X.509 SVIDs (via
//! [`kakuin-workload-api`](https://github.com/pleme-io/kakuin-workload-api))
//! to rustls Server/Client configs with identity-aware peer
//! verification.
//!
//! Sprint **M1.3** of `theory/MESH-EXECUTION-PLAN.md`. Bare-metal
//! proof of mTLS-via-SPIFFE: two Rust Servicos handshake with SVID-
//! sourced certs and reject any peer whose SPIFFE-ID isn't in the
//! allow-list.
//!
//! # Architecture
//!
//! ```text
//!   +--------------------------+      +-----------------------------+
//!   | kakuin-workload-api      | ---> | kakuin-rustls               |
//!   |   X509SvidUpdate stream  |      |   ArcSwap<rustls::Config>   |
//!   +--------------------------+      |   SpiffeIdVerifier          |
//!                                     +-----------------------------+
//!                                              |
//!                                              v
//!                                   rustls::ServerConfig (or ClientConfig)
//!                                   handed to your TLS terminator
//! ```
//!
//! # Quickstart
//!
//! ```no_run
//! use kakuin_workload_api::WorkloadApiClient;
//! use kakuin_rustls::{ServerConfigBuilder, SpiffeIdAllowList};
//!
//! # async fn ex() -> Result<(), Box<dyn std::error::Error>> {
//! let mut client = WorkloadApiClient::default().await?;
//! let svid = client.fetch_x509_svid().await?;
//!
//! // Build a server-side mTLS config that requires peers to present
//! // a SPIFFE-ID matching the allow-list.
//! let allow = SpiffeIdAllowList::exact_ids([
//!     "spiffe://pleme.io/ns/openclaw/sa/lacre".to_string(),
//!     "spiffe://pleme.io/ns/openclaw/sa/openclaw-stack-scanner".to_string(),
//! ]);
//! let server_cfg = ServerConfigBuilder::new(svid).peer_allowlist(allow).build()?;
//! // hand server_cfg to tokio-rustls TlsAcceptor::from(Arc::new(server_cfg))
//! # let _ = server_cfg;
//! # Ok(())
//! # }
//! ```

#![warn(clippy::pedantic)]
#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]

use std::sync::Arc;

use kakuin_workload_api::X509Svid;
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::ClientCertVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

mod verifier;
pub use verifier::{PeerIdentity, SpiffeIdAllowList, SpiffeIdVerifier};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("x509 parse: {0}")]
    X509(String),
    #[error("rustls: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("invalid certificate chain: {0}")]
    InvalidChain(String),
    #[error("invalid private key: {0}")]
    InvalidKey(String),
    #[error("trust bundle parse failed: {0}")]
    TrustBundle(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Builder for a `rustls::ServerConfig` backed by a SPIFFE SVID.
///
/// Required: an `X509Svid` (cert chain + private key + bundle).
/// Optional: `peer_allowlist` — without it, *any* SVID-bearing peer
/// from the trust domain is accepted (still strong, but anyone with
/// an SVID can talk to you). With it, only peers whose URI SAN
/// matches the allow-list pass.
pub struct ServerConfigBuilder {
    svid: X509Svid,
    peer_allowlist: Option<SpiffeIdAllowList>,
}

impl ServerConfigBuilder {
    #[must_use]
    pub fn new(svid: X509Svid) -> Self {
        Self {
            svid,
            peer_allowlist: None,
        }
    }

    #[must_use]
    pub fn peer_allowlist(mut self, allow: SpiffeIdAllowList) -> Self {
        self.peer_allowlist = Some(allow);
        self
    }

    /// Build the rustls `ServerConfig`. Requires client certs;
    /// validates the chain against the SVID's trust bundle and the
    /// peer's SPIFFE-ID against the allow-list (if set).
    pub fn build(self) -> Result<ServerConfig> {
        let chain = decode_cert_chain(&self.svid.cert_chain_der)?;
        let key = decode_private_key(&self.svid.private_key_der)?;
        let roots = build_root_store(&self.svid.bundle_der)?;
        let verifier = make_client_verifier(roots, self.peer_allowlist)?;

        let cfg = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(chain, key)?;
        Ok(cfg)
    }
}

/// Builder for a `rustls::ClientConfig` backed by a SPIFFE SVID.
///
/// Use this when your code is the *client* side of an mTLS edge —
/// you present an SVID-derived cert and validate the *server*'s
/// SPIFFE-ID against the allow-list.
pub struct ClientConfigBuilder {
    svid: X509Svid,
    peer_allowlist: Option<SpiffeIdAllowList>,
}

impl ClientConfigBuilder {
    #[must_use]
    pub fn new(svid: X509Svid) -> Self {
        Self {
            svid,
            peer_allowlist: None,
        }
    }

    #[must_use]
    pub fn peer_allowlist(mut self, allow: SpiffeIdAllowList) -> Self {
        self.peer_allowlist = Some(allow);
        self
    }

    pub fn build(self) -> Result<ClientConfig> {
        let chain = decode_cert_chain(&self.svid.cert_chain_der)?;
        let key = decode_private_key(&self.svid.private_key_der)?;
        let roots = build_root_store(&self.svid.bundle_der)?;
        let verifier: Arc<dyn ServerCertVerifier> =
            Arc::new(SpiffeIdVerifier::server(roots, self.peer_allowlist));

        let cfg = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(chain, key)?;
        Ok(cfg)
    }
}

fn decode_cert_chain(der: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    // The SPIFFE Workload API delivers the chain as a concatenated
    // DER blob (leaf followed by intermediates). Walk DER lengths to
    // split it.
    let mut out = Vec::new();
    let mut rest: &[u8] = der;
    while !rest.is_empty() {
        let (next, consumed) = consume_one_der(rest)?;
        out.push(CertificateDer::from(consumed.to_vec()));
        rest = next;
    }
    if out.is_empty() {
        return Err(Error::InvalidChain("empty chain".into()));
    }
    Ok(out)
}

fn decode_private_key(der: &[u8]) -> Result<PrivateKeyDer<'static>> {
    if der.is_empty() {
        return Err(Error::InvalidKey("empty key".into()));
    }
    Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der.to_vec())))
}

fn build_root_store(bundle_der: &[u8]) -> Result<Arc<RootCertStore>> {
    let mut store = RootCertStore::empty();
    let mut rest: &[u8] = bundle_der;
    while !rest.is_empty() {
        let (next, consumed) = consume_one_der(rest)?;
        store
            .add(CertificateDer::from(consumed.to_vec()))
            .map_err(|e| Error::TrustBundle(format!("rustls add: {e}")))?;
        rest = next;
    }
    if store.is_empty() {
        return Err(Error::TrustBundle("no roots in bundle".into()));
    }
    Ok(Arc::new(store))
}

/// Walk one DER-encoded structure (TLV) at the start of `bytes`.
/// Returns `(remaining, consumed)`.
fn consume_one_der(bytes: &[u8]) -> Result<(&[u8], &[u8])> {
    if bytes.len() < 2 {
        return Err(Error::X509(format!("truncated DER ({} bytes)", bytes.len())));
    }
    // Tag byte (always 0x30 for SEQUENCE) + length encoding.
    let len_byte = bytes[1];
    let (header_len, total_len) = if len_byte & 0x80 == 0 {
        // Short form.
        (2usize, 2usize + usize::from(len_byte))
    } else {
        let n = usize::from(len_byte & 0x7f);
        if n == 0 || n > 4 {
            return Err(Error::X509(format!("unsupported length octets: {n}")));
        }
        if bytes.len() < 2 + n {
            return Err(Error::X509("truncated length".into()));
        }
        let mut len = 0usize;
        for &b in &bytes[2..2 + n] {
            len = (len << 8) | usize::from(b);
        }
        (2 + n, 2 + n + len)
    };
    if bytes.len() < total_len {
        return Err(Error::X509(format!(
            "truncated DER body: need {}, have {}",
            total_len,
            bytes.len()
        )));
    }
    let _ = header_len;
    Ok((&bytes[total_len..], &bytes[..total_len]))
}

fn make_client_verifier(
    roots: Arc<RootCertStore>,
    allow: Option<SpiffeIdAllowList>,
) -> Result<Arc<dyn ClientCertVerifier>> {
    if allow.is_none() {
        // No SPIFFE-ID allow-list — fall back to plain webpki against
        // the SVID's trust bundle (any cert from this trust domain
        // accepted).
        let v = WebPkiClientVerifier::builder(roots)
            .build()
            .map_err(|e| Error::TrustBundle(format!("WebPkiClientVerifier::build: {e}")))?;
        return Ok(v);
    }
    Ok(Arc::new(SpiffeIdVerifier::client(roots, allow)))
}

/// Server-name shim used by the test helpers — clients calling our
/// in-mesh endpoints can present an arbitrary placeholder name; we
/// validate solely on SPIFFE-ID. A future revision can map server
/// names to expected SPIFFE-IDs (1:1 routing).
#[must_use]
pub fn spiffe_placeholder_server_name() -> ServerName<'static> {
    ServerName::try_from("spiffe.local").expect("static")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_chain_is_error() {
        let svid = X509Svid {
            spiffe_id: "spiffe://pleme.io/ns/x/sa/y".into(),
            cert_chain_der: vec![],
            private_key_der: vec![1, 2, 3],
            bundle_der: vec![],
            hint: String::new(),
        };
        let err = ServerConfigBuilder::new(svid).build().unwrap_err();
        match err {
            Error::InvalidChain(_) => {}
            other => panic!("unexpected: {other:?}"),
        }
    }
}
