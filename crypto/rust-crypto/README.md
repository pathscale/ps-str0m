# ps-str0m-rust-crypto

`ps-str0m-rust-crypto` is the selected RustCrypto provider for the
[str0m](https://github.com/algesten/str0m) Sans-I/O WebRTC stack. It supplies
DTLS, SRTP, STUN HMAC, and certificate-fingerprint operations through
str0m-proto's `CryptoProvider` interface.

The package retains inherited `str0m-rust-crypto` implementation code from the
upstream str0m repository. The release line starts at `0.1.0` and is maintained
in the
[pathscale/ps-str0m](https://github.com/pathscale/ps-str0m) repository. The
provider package is intentionally independent of the repository workspace: its
release manifest uses caret-versioned published dependencies and contains no
git or path dependency.

## Architecture and selected graph

The provider is a set of static Rust trait implementations. It owns no socket,
thread, async runtime, page binding, media frame, capture device, or codec.
The str0m adapter supplies packets and time; the application owns sockets,
queues, lifecycle, and shutdown.

Certificate generation is local to this package. It creates an ephemeral P-256
self-signed certificate with `p256` and `x509-cert` and returns the DER
certificate and PKCS#8 private key required by dimpl. This removes the old
`dimpl/rcgen` feature edge from this provider. The selected graph is:

```text
ps-str0m-rust-crypto 0.1.x
├── str0m-proto ^0.7.0 (dtls)
├── dimpl ^0.7.4 (rust-crypto, default-features = false)
├── p256 ^0.13
├── x509-cert ^0.2 (builder)
└── RustCrypto AES, CTR, HMAC, SHA-1, and SHA-2 crates
```

The selected profile does not enable dimpl's `rcgen` or `aws-lc-rs` features.
It must not pull `aws-lc-sys`, `ring`, OpenSSL, a C/C++ build, or an
unapproved native crypto edge. The `ps-str0m` root package retains upstream
optional native backends for explicit compatibility choices; they are excluded
from the Rust-only default profile and this package makes no all-features
purity claim.

## Usage

Use the provider directly with a str0m `Rtc` instance:

```toml
[dependencies]
ps-str0m-rust-crypto = "0.1"
str0m = { version = "0.24", default-features = false }
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
`rust-crypto` feature. Applications using that profile must disable default
features explicitly when they need a Rust-only graph.

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
[str0m-proto](https://crates.io/crates/str0m-proto),
[dimpl](https://crates.io/crates/dimpl),
[p256](https://crates.io/crates/p256),
[x509-cert](https://crates.io/crates/x509-cert),
[aes-gcm](https://crates.io/crates/aes-gcm),
[aes](https://crates.io/crates/aes),
[ctr](https://crates.io/crates/ctr),
[hmac](https://crates.io/crates/hmac),
[sha1](https://crates.io/crates/sha1), and
[sha2](https://crates.io/crates/sha2). The release review records the exact
resolved graph separately; this README does not treat crate names or feature
labels as proof of implementation purity.

## Required acceptance

Publishing or using this provider as the Chuzz default requires all of the
following evidence against the exact release source:

1. Normal and build dependency graphs for the selected feature set contain no
   `aws-lc-rs`, `aws-lc-sys`, `ring`, OpenSSL, C/C++ build, or unapproved
   native edge. Optional native backends in the root workspace remain explicit
   exclusions rather than an all-features purity claim.
2. Provider construction produces a parseable DER certificate and matching
   P-256 public/private key. The DTLS peer verifies the certificate fingerprint
   and completes a real handshake, including retransmission and close paths.
3. A two-peer SRTP loopback encrypts and decrypts real packets with the
   negotiated profile, increments send/receive counters, and rejects altered
   authentication data.
4. A `ps-str0m` Rust-only configuration using
   `default-features = false, features = ["rust-crypto"]` completes the same
   DTLS/SRTP loopback without selecting an alternate provider.

Until those checks pass, this package is a release candidate and the root
project must not describe it as a verified WebRTC or Chuzz media endpoint.
