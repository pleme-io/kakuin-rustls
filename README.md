# kakuin-rustls

Bridge SPIFFE X.509 SVIDs (delivered via
[`kakuin-workload-api`](https://github.com/pleme-io/kakuin-workload-api))
to rustls `ServerConfig` / `ClientConfig` with **identity-aware peer
verification** — peers must present a SPIFFE-ID matching a typed
allow-list, on top of standard X.509 chain validation.

Sprint **M1.3** of [`pleme-io/theory/MESH-EXECUTION-PLAN.md`](https://github.com/pleme-io/theory/blob/main/MESH-EXECUTION-PLAN.md).

## Two layers of validation

```
peer cert  →  webpki chain validation against SVID's trust bundle
           →  SPIFFE-ID extraction from URI SAN
           →  exact-match against caller-supplied allow-list
```

Standard X.509 chain check first (proves the cert was issued by the
trust domain's CA), *then* the SPIFFE-ID gate (proves it's a specific
named workload, not just *some* workload in the trust domain).

## Quickstart

### Server-side mTLS (e.g. cartorio accepting from lacre)

```rust
use kakuin_workload_api::WorkloadApiClient;
use kakuin_rustls::{ServerConfigBuilder, SpiffeIdAllowList};

let mut client = WorkloadApiClient::default().await?;
let svid = client.fetch_x509_svid().await?;

let allow = SpiffeIdAllowList::exact_ids([
    "spiffe://pleme.io/ns/openclaw/sa/lacre".to_string(),
    "spiffe://pleme.io/ns/openclaw/sa/openclaw-stack-scanner".to_string(),
]);

let server_cfg = ServerConfigBuilder::new(svid)
    .peer_allowlist(allow)
    .build()?;

let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_cfg));
```

### Client-side mTLS (e.g. lacre dialing cartorio)

```rust
use kakuin_rustls::{ClientConfigBuilder, SpiffeIdAllowList, spiffe_placeholder_server_name};

let allow = SpiffeIdAllowList::exact_ids([
    "spiffe://pleme.io/ns/openclaw/sa/openclaw-stack-cartorio".to_string(),
]);

let client_cfg = ClientConfigBuilder::new(svid)
    .peer_allowlist(allow)
    .build()?;
```

## License

Dual MIT OR Apache-2.0.
