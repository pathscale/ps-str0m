# Release: ps-str0m

The fork publishes four production packages. Their library imports retain the
existing names. In ps-str0m 0.26 and ps-str0m-is 0.12, callers must handle
errors when creating random ICE credentials, initializing RTC, or requesting
an SDP ICE restart. Standalone ICE users must also handle errors when driving
ICE timeouts or creating STUN transaction IDs.

| Publish order | Package | Version | Library import |
| --- | --- | --- | --- |
| 1 | ps-str0m-proto | 0.8.1 | str0m_proto |
| 2 | ps-str0m-is | 0.12.0 | is |
| 3 | ps-str0m-rust-crypto | 0.2.1 | ps_str0m_rust_crypto |
| 4 | ps-str0m | 0.26.0 | str0m |

`ps-dimpl 0.8.0` is already published and is an external registry dependency.
The fork's production graph is:

```text
ps-str0m 0.26.0
├── ps-str0m-proto ^0.8.1
│   └── ps-dimpl ^0.8.0 (dtls feature)
├── ps-str0m-is ^0.12.0
│   └── ps-str0m-proto ^0.8.1
├── ps-str0m-rust-crypto ^0.2.1 (default rust-crypto feature)
│   ├── ps-str0m-proto ^0.8.1
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

## Manual publication

Bump the affected package versions and update the workspace dependency ranges
as needed. Check that any new external dependency versions are on crates.io.
Verify the release source locally, review the package names and dependency
ranges, and rebase-merge the reviewed change onto `master`.

In GitHub Actions, manually run the **Publish** workflow from `master`. Select
the checkbox for each package you intend to publish. All four inputs default
to false, so an empty selection publishes nothing. The workflow uses the
repository's `CARGO_REGISTRY_TOKEN` for crates.io.

The workflow publishes selected packages in the order above. It calls
`cargo publish --registry crates-io --manifest-path` for each selected
manifest. Cargo uses the version in that manifest, verifies the package, and
rejects versions already published. To resume a partial release, wait until
the required dependency versions are indexed on crates.io, then dispatch the
workflow again with only the still-unpublished package versions selected.

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
