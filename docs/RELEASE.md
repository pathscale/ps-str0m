# Release: `ps-str0m-rust-crypto`

This fork keeps the root package name `str0m` for API and feature compatibility.
The root package is the `ps-str0m` fork harness in this release lane; the owned
publishable leaf is renamed to `ps-str0m-rust-crypto` and starts at `0.1.0`.

This document covers that leaf only. It does not publish the inherited upstream
workspace crates or the root `str0m` harness.

## Package boundary

```text
str0m (ps-str0m fork harness; not a publication target in this lane)
  └── rust-crypto feature
        └── ps-str0m-rust-crypto 0.1.0
              ├── str0m-proto ^0.7 (published dependency)
              ├── dimpl ^0.7 (published dependency, rust-crypto feature)
              └── RustCrypto provider and certificate extraction
```

The provider retains inherited implementation code from upstream
`crypto/rust-crypto`. The fork-owned changes are the package identity,
certificate-generation seam, and dependency feature selection. The leaf
contains `LICENSE-MIT.txt` and `LICENSE-APACHE.txt`; its manifest remains
`MIT OR Apache-2.0`.

The following packages remain external or inherited and are not publication
commands for this lane:

- `str0m-proto`
- `is`
- `str0m-netem`

The root package exposes the `rust-crypto` feature as its only crypto backend.

## Preconditions

Before publication, root must verify the exact candidate source and resolved
published dependency graph:

1. The provider manifest has no git or path dependency and uses published caret
   versions for `str0m-proto`, `dimpl`, and its RustCrypto/X.509 dependencies.
2. The selected graph excludes `rcgen`, `aws-lc-rs`, `aws-lc-sys`, `ring`,
   OpenSSL, `cc`, bindgen, and unapproved native crypto edges.
3. The package includes the README, source, `LICENSE-MIT.txt`, and
   `LICENSE-APACHE.txt` in `cargo package --list`.
4. The certificate source fix has passed the root compile. The generated DER
   certificate must match its P-256 private key and expose the fingerprint used
   by the DTLS peer.
5. Two provider-backed DTLS peers complete handshake, retransmission,
   certificate verification, application data, and close. A real SRTP loopback
   encrypts/decrypts packets, advances send/receive counters, and rejects
   altered authentication data.
6. The root harness with
   `default-features = false, features = ["rust-crypto"]` selects this leaf
   and completes the same DTLS/SRTP acceptance. Root owns the lockfile and
   integration evidence.

## Fork-only local QA

When testing the unpublished fork checkout against local provider or proto
paths, use the opt-in wrapper and its ignored `.cargo/local-engine.toml`:

```sh
scripts/local-engine.sh check -p str0m --no-default-features --features rust-crypto
scripts/local-engine.sh test -p str0m --no-default-features --features rust-crypto --test handshake-direct
```

The wrapper refuses concurrent invocations, keeps its lock snapshot below the
repository's `.cargo` directory, and restores or removes `Cargo.lock` on every
exit path. It is only for fork-local checks. The wrapper must not be used for
the packaged leaf verification below: that check must resolve the published
caret dependencies without a local patch.

## Leaf-only release procedure

The only publication command in this lane is:

```sh
cargo package --list -p ps-str0m-rust-crypto
cargo publish --dry-run -p ps-str0m-rust-crypto
cargo publish -p ps-str0m-rust-crypto
```

Wait for the package to be indexed, then verify its published metadata and
version through crates.io. Do not add publication commands for the inherited
workspace crates or for the root `str0m` harness to this release.

If a future release changes the `str0m-proto` or `dimpl` compatibility range,
coordinate that shared dependency decision before bumping this leaf. Do not
publish a second copy against an incompatible unpublished protocol crate.

## License provenance

The leaf inherits the upstream str0m MIT/Apache-2.0 license expression and
carries both license texts in its own package directory. Its provider source is
inherited from the upstream str0m RustCrypto backend at commit
`393a3d238aa466ba9edc52fba823f86563642c20`, with the fork changes described in
the leaf README. Dependency licenses and source provenance are taken from the
published crate manifests; no third-party dependency source is vendored into
the leaf.

