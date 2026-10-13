use str0m_proto::crypto as provider;

pub use provider::{AeadChacha20Poly1305, AeadChacha20Poly1305Cipher, CryptoProvider, CryptoSafe};
pub use provider::{Sha1HmacProvider, Sha256Provider};
pub use provider::{SrtpProvider, SupportedAeadChacha20Poly1305};

/// DTLS related types and traits.
pub mod dtls {
    pub use super::provider::dtls::{DtlsInstance, DtlsProvider};

    pub use dimpl::DtlsCertificate as DtlsCert;
    pub use dimpl::KeyingMaterial;
    pub use dimpl::ProtocolVersion;
    pub use dimpl::SrtpProfile;
    // Note: dimpl::Error is renamed to DtlsImplError to avoid conflict with str0m's DtlsError
    pub use super::provider::DtlsVersion;
    pub use dimpl::{Error as DtlsImplError, Output as DtlsOutput};
}

#[cfg(any(test, feature = "_internal_test_exports"))]
#[allow(unused)]
pub(crate) fn test_default_provider() -> &'static CryptoProvider {
    use std::sync::OnceLock;
    static TEST_PROVIDER: OnceLock<CryptoProvider> = OnceLock::new();
    TEST_PROVIDER.get_or_init(from_feature_flags)
}

/// Create the crypto provider selected by feature flags.
///
/// The fork has one backend: the pure-Rust ChaCha20-Poly1305 `rust-crypto` provider.
#[allow(unreachable_code, clippy::needless_return)]
pub fn from_feature_flags() -> CryptoProvider {
    #[cfg(feature = "rust-crypto")]
    return str0m_rust_crypto::default_provider();

    panic!(
        "No crypto provider available: enable the rust-crypto feature or install a CryptoProvider"
    );
}

mod finger;
pub use finger::Fingerprint;

pub use str0m_proto::crypto::{CryptoError, DtlsError};
