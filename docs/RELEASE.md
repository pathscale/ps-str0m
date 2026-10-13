# Release: ps-str0m

The fork publishes four production packages. Their library imports retain the
existing names, so downstream Rust source does not need to change.

| Publish order | Package | Version | Library import |
| --- | --- | --- | --- |
| 1 | ps-str0m-proto | 0.8.0 | str0m_proto |
| 2 | ps-str0m-is | 0.11.1 | is |
| 3 | ps-str0m-rust-crypto | 0.2.0 | ps_str0m_rust_crypto |
| 4 | ps-str0m | 0.25.0 | str0m |

`ps-dimpl 0.8.0` is already published and is an external registry dependency.
The fork's production graph is:

```text
ps-str0m 0.25.0
├── ps-str0m-proto ^0.8.0
│   └── ps-dimpl ^0.8.0 (dtls feature)
├── ps-str0m-is ^0.11.1
│   └── ps-str0m-proto ^0.8.0
├── ps-str0m-rust-crypto ^0.2.0 (default rust-crypto feature)
│   ├── ps-str0m-proto ^0.8.0
│   └── ps-dimpl ^0.8.0 (rust-crypto, default-features = false)
└── external Rust dependencies
```

The only built-in crypto provider uses pure-Rust ChaCha20-Poly1305 for DTLS
and SRTP, with HKDF-SHA256 for SRTP session keys and salts. The example web
servers expose HTTP signaling behind an external TLS reverse proxy.

## Package boundaries

Every production package declares its license, description, repository, and
README. Local production dependencies carry both a caret version and a path;
Cargo rewrites the paths to registry dependencies in published packages.

`ps-str0m-netem 0.4.0` is a development-only network emulator with
`publish = false`. `_str0m_test 0.1.0` is an unpublished feature-enabling
helper. Both are path-only root dev dependencies so Cargo omits them from the
published manifest. `str0m-fuzz 0.0.0` is excluded from the workspace and has
`publish = false`. None of these packages belongs in the publish order.

## Automated publication

`.github/workflows/publish.yml` follows the house convention: production
manifest changes on `main` trigger publication on `ubicloud-standard-2`.
Manual dispatch on `main` can bootstrap or resume the release. Configure the
repository secret `CARGO_REGISTRY_TOKEN` with permission to publish all four
production package names.

The workflow runs the four package steps in the order above. Each step checks
the manifest's version on crates.io once. An existing, non-yanked version is
skipped; a missing version is published with ordinary `cargo publish -p`,
including Cargo's package verification. Registry lookup errors, yanked
versions, and publish failures stop the job. Later version bumps therefore
publish only missing versions, and a partially completed release can resume.

For a release, bump the affected package versions and the workspace dependency
ranges together, then merge onto `main`. Ensure any new external dependency
versions are already published. Publication is irreversible, so review the
package names, dependency ranges, and release source before merging.

The equivalent first-publication order is:

```text
cargo publish -p ps-str0m-proto
cargo publish -p ps-str0m-is
cargo publish -p ps-str0m-rust-crypto
cargo publish -p ps-str0m
```

Once the four versions are indexed, downstream workspaces can remove their
`ps-str0m` and `ps-str0m-rust-crypto` path patches. Published `ps-dimpl 0.8.0`
already supplies the provider API, so a dimpl path patch is unnecessary unless
the consumer separately needs changes newer than that release.

## License provenance

The provider inherits the upstream str0m MIT/Apache-2.0 license expression and
carries both license texts in its own package directory. Its provider source is
inherited from the upstream str0m RustCrypto backend at commit
`393a3d238aa466ba9edc52fba823f86563642c20`, with the fork changes described in
the provider README. Dependency licenses and source provenance come from the
published crate manifests and the resolved release graph.

Publication metadata and a successful upload do not establish media-session
behavior. Runtime acceptance evidence belongs with the exact released source.
