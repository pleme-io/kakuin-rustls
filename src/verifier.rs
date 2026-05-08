//! SPIFFE-ID-aware peer cert verifier.
//!
//! Wraps rustls's webpki verifier to first run the standard X.509
//! chain validation against the SVID's trust bundle, then extracts
//! the URI SAN from the leaf, parses it as a SPIFFE-ID, and gates on
//! the allow-list.

use std::sync::Arc;

use rustls::DigitallySignedStruct;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DistinguishedName, RootCertStore, SignatureScheme};
use x509_cert::der::Decode;

/// Allow-list of acceptable peer SPIFFE-IDs.
///
/// Today supports exact-string match. Future iterations can add
/// trust-domain-only matching, prefix patterns, or template
/// matching via a typed predicate.
#[derive(Debug, Clone)]
pub struct SpiffeIdAllowList {
    exact: Vec<String>,
}

impl SpiffeIdAllowList {
    /// Allow exactly these SPIFFE-IDs (case-sensitive).
    pub fn exact_ids<I: IntoIterator<Item = String>>(ids: I) -> Self {
        Self {
            exact: ids.into_iter().collect(),
        }
    }

    fn permits(&self, spiffe_id: &str) -> bool {
        self.exact.iter().any(|x| x == spiffe_id)
    }
}

/// Identity surfaced after a successful SPIFFE-aware handshake.
#[derive(Debug, Clone)]
pub struct PeerIdentity {
    pub spiffe_id: String,
}

/// Combined webpki + SPIFFE-ID verifier.
///
/// Used as both a `ClientCertVerifier` (server-side mTLS, `Mode::Client`)
/// and `ServerCertVerifier` (client-side mTLS, `Mode::Server`).
pub struct SpiffeIdVerifier {
    inner_client: Option<Arc<dyn ClientCertVerifier>>,
    inner_server: Option<Arc<dyn ServerCertVerifier>>,
    allow: Option<SpiffeIdAllowList>,
    /// Held only for the client-mode (verify_server_cert) path —
    /// SPIFFE certs have no DNS SAN so we bypass webpki's name check
    /// and validate the chain manually via `EndEntityCert::verify_for_usage`.
    roots: Option<Arc<RootCertStore>>,
}

impl SpiffeIdVerifier {
    /// Build a verifier in "server-side mTLS" mode — used by a server
    /// to validate *client* certs.
    #[must_use]
    pub fn client(roots: Arc<RootCertStore>, allow: Option<SpiffeIdAllowList>) -> Self {
        let inner = WebPkiClientVerifier::builder(roots.clone())
            .build()
            .expect("WebPkiClientVerifier::build");
        Self {
            inner_client: Some(inner),
            inner_server: None,
            allow,
            roots: Some(roots),
        }
    }

    /// Build a verifier in "client-side mTLS" mode — used by a
    /// client to validate the *server*'s cert.
    #[must_use]
    pub fn server(roots: Arc<RootCertStore>, allow: Option<SpiffeIdAllowList>) -> Self {
        // We keep WebPkiServerVerifier around for the signature-
        // verification helpers, but `verify_server_cert` itself
        // bypasses it and validates the chain manually so we can
        // skip the DNS-name check (SPIFFE certs have URI SAN only).
        let inner = WebPkiServerVerifier::builder(roots.clone())
            .build()
            .expect("WebPkiServerVerifier::build");
        Self {
            inner_client: None,
            inner_server: Some(inner),
            allow,
            roots: Some(roots),
        }
    }

    fn check_spiffe_id(&self, end_entity: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        let cert =
            x509_cert::Certificate::from_der(end_entity.as_ref()).map_err(|e| {
                rustls::Error::General(format!("kakuin: x509 parse failed: {e}"))
            })?;
        let spiffe_id = extract_spiffe_id(&cert)
            .ok_or_else(|| rustls::Error::General("kakuin: no SPIFFE-ID in URI SAN".into()))?;

        if let Some(allow) = &self.allow {
            if !allow.permits(&spiffe_id) {
                return Err(rustls::Error::General(format!(
                    "kakuin: peer SPIFFE-ID {spiffe_id} not in allow-list"
                )));
            }
        }
        // Tracing for observability — an L7 layer can pluck this
        // from peer certs at the connection level too.
        tracing::debug!(spiffe_id, "kakuin: peer accepted");
        Ok(())
    }
}

fn extract_spiffe_id(cert: &x509_cert::Certificate) -> Option<String> {
    // SubjectAlternativeName extension OID = 2.5.29.17.
    use x509_cert::der::asn1::Ia5String;
    use x509_cert::der::oid::ObjectIdentifier;
    let san_oid: ObjectIdentifier = "2.5.29.17".parse().ok()?;
    let extensions = cert.tbs_certificate.extensions.as_ref()?;
    for ext in extensions {
        if ext.extn_id == san_oid {
            if let Ok(san) = x509_cert::ext::pkix::SubjectAltName::from_der(ext.extn_value.as_bytes()) {
                for general_name in &san.0 {
                    if let x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(
                        Ia5String { .. },
                    ) = general_name
                    {
                        // Re-encode the GeneralName to get the URI's
                        // string content. Easier: walk Display impl.
                        let s = general_name_to_uri(general_name);
                        if let Some(s) = s {
                            if s.starts_with("spiffe://") {
                                return Some(s);
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

fn general_name_to_uri(gn: &x509_cert::ext::pkix::name::GeneralName) -> Option<String> {
    use x509_cert::ext::pkix::name::GeneralName;
    if let GeneralName::UniformResourceIdentifier(uri) = gn {
        return Some(uri.to_string());
    }
    None
}

impl std::fmt::Debug for SpiffeIdVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpiffeIdVerifier")
            .field("allow", &self.allow.as_ref().map(|a| a.exact.len()))
            .finish()
    }
}

impl ClientCertVerifier for SpiffeIdVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner_client
            .as_ref()
            .map(|i| i.root_hint_subjects())
            .unwrap_or(&[])
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let inner = self
            .inner_client
            .as_ref()
            .expect("SpiffeIdVerifier configured for client-side mTLS");
        let verified = inner.verify_client_cert(end_entity, intermediates, now)?;
        self.check_spiffe_id(end_entity)?;
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner_client
            .as_ref()
            .expect("client-mode")
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner_client
            .as_ref()
            .expect("client-mode")
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner_client
            .as_ref()
            .map(|i| i.supported_verify_schemes())
            .unwrap_or_default()
    }
}

impl ServerCertVerifier for SpiffeIdVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // SPIFFE X.509 SVIDs carry ONLY a URI SAN
        // (`spiffe://<trust-domain>/ns/.../sa/...`) — no DNS SAN, no IP
        // SAN. rustls's default WebPkiServerVerifier validates the
        // chain AND checks DNS-name match against the SNI; that DNS
        // check fails ("certificate not valid for name X") because
        // there's no DNS SAN to match.
        //
        // Verify the chain ourselves via rustls-webpki's
        // `EndEntityCert::verify_for_usage` (chain + signature +
        // validity) and SKIP the DNS check. SPIFFE-ID URI SAN
        // matching is done in `check_spiffe_id` below.
        let roots = self
            .roots
            .as_ref()
            .ok_or_else(|| rustls::Error::General("kakuin: missing roots".into()))?;

        let cert = webpki::EndEntityCert::try_from(end_entity)
            .map_err(|e| rustls::Error::General(format!("kakuin: parse leaf: {e}")))?;

        cert.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &roots.roots,
            intermediates,
            now,
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .map_err(|e| rustls::Error::General(format!("kakuin: chain validation: {e}")))?;

        self.check_spiffe_id(end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner_server
            .as_ref()
            .expect("server-mode")
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner_server
            .as_ref()
            .expect("server-mode")
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner_server
            .as_ref()
            .map(|i| i.supported_verify_schemes())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_permits_only_listed_ids() {
        let allow = SpiffeIdAllowList::exact_ids(vec![
            "spiffe://pleme.io/ns/openclaw/sa/lacre".to_string(),
            "spiffe://pleme.io/ns/openclaw/sa/scanner".to_string(),
        ]);
        assert!(allow.permits("spiffe://pleme.io/ns/openclaw/sa/lacre"));
        assert!(allow.permits("spiffe://pleme.io/ns/openclaw/sa/scanner"));
        assert!(!allow.permits("spiffe://pleme.io/ns/openclaw/sa/cartorio"));
        assert!(!allow.permits("spiffe://attacker.example/ns/x/sa/y"));
    }

    #[test]
    fn allowlist_is_case_sensitive() {
        let allow = SpiffeIdAllowList::exact_ids(vec!["spiffe://pleme.io/ns/x/sa/y".into()]);
        assert!(!allow.permits("spiffe://Pleme.IO/ns/x/sa/y"));
    }
}
