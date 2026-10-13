# ps-str0m-rust-crypto

`ps-str0m-rust-crypto` is the RustCrypto provider for the
[ps-str0m](https://github.com/pathscale/ps-str0m) Sans-I/O WebRTC stack. It supplies
DTLS, SRTP, STUN HMAC, and certificate-fingerprint operations through
str0m-proto's `CryptoProvider` interface.

The package retains inherited `str0m-rust-crypto` implementation code from the
upstream str0m repository. The current release is `0.2.0`, maintained in the
[pathscale/ps-str0m](https://github.com/pathscale/ps-str0m) repository. Workspace
dependencies use local paths and caret versions; Cargo replaces those paths
with registry dependencies when packaging for publication.

## Architecture and selected graph

The provider is a set of static Rust trait implementations. It owns no socket,
thread, async runtime, page binding, media frame, capture device, or codec.
The str0m adapter supplies packets and time; the application owns sockets,
queues, lifecycle, and shutdown.

Certificate generation is local to this package. It creates an ephemeral P-256
self-signed certificate with `p256` and `x509-cert` and returns the DER
certificate and PKCS#8 private key required by dimpl. The selected graph is:

```text
ps-str0m-rust-crypto 0.2.0
├── ps-str0m-proto ^0.8.0 (dtls)
├── ps-dimpl ^0.8.0 (rust-crypto, default-features = false)
├── p256 ^0.13
├── x509-cert ^0.2 (builder)
└── RustCrypto ChaCha20-Poly1305, HKDF, HMAC, SHA-1, and SHA-2 crates
```

The provider and the root package use only pure-Rust crypto. ChaCha20-Poly1305
is the only SRTP profile, and session keys and salts use HKDF-SHA256.

## Usage

Use the provider directly with a str0m `Rtc` instance:

```toml
[dependencies]
ps-str0m-rust-crypto = "^0.2"
str0m = { package = "ps-str0m", version = "^0.25", default-features = false }
```

```rust
use std::sync::Arc;
use std::time::Instant;

use ps_str0m_rust_crypto::default_provider;
use str0m::Rtc;

let rtc = Rtc::builder()
    .set_crypto_provider(Arc::new(default_provider()))
    .build(Instant::now());
```

The `ps-str0m` root package also exposes this provider through its
`rust-crypto` feature, which is enabled by default.

## License and provenance

This package is distributed under `MIT OR Apache-2.0`, matching the inherited
upstream str0m provider. The package includes both license texts next to this
README. Its provider implementation retains inherited code from the upstream
`crypto/rust-crypto` directory; the fork changes the package identity,
certificate-generation seam, and dependency feature selection. The source seam
was reviewed against upstream str0m commit
`393a3d238aa466ba9edc52fba823f86563642c20` in the
[pathscale/ps-str0m fork](https://github.com/pathscale/ps-str0m). No unrelated
third-party source is vendored into this package. Dependency license and source
provenance come from the published crate manifests for
[ps-str0m-proto](https://crates.io/crates/ps-str0m-proto),
[ps-dimpl](https://crates.io/crates/ps-dimpl),
[p256](https://crates.io/crates/p256),
[x509-cert](https://crates.io/crates/x509-cert),
[chacha20poly1305](https://crates.io/crates/chacha20poly1305),
[hkdf](https://crates.io/crates/hkdf),
[hmac](https://crates.io/crates/hmac),
[sha1](https://crates.io/crates/sha1), and
[sha2](https://crates.io/crates/sha2). The release review records the exact
resolved graph separately; this README does not treat crate names or feature
labels as proof of implementation purity.

## Provider example

The existing `examples/provider-probe.rs` checks certificate DER, the matching
P-256 private key, the certificate self-signature, the SHA-256 fingerprint, and
ChaCha20-Poly1305 encryption, decryption, and rejection of an altered tag.
These provider operations do not establish a negotiated two-peer media session.

See [the release procedure](../../docs/RELEASE.md) for the publication order.
