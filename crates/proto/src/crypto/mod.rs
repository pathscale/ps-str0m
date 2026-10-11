mod provider;
pub use provider::{AeadChacha20Poly1305, AeadChacha20Poly1305Cipher, CryptoProvider, CryptoSafe};
pub use provider::{DtlsVersion, Sha1HmacProvider, Sha256Provider};
pub use provider::{SrtpProvider, SupportedAeadChacha20Poly1305};

mod error;
pub use error::{CryptoError, DtlsError};

/// DTLS related types and traits.
pub mod dtls {
    pub use super::provider::{DtlsInstance, DtlsProvider};

    pub use dimpl::CryptoError as DtlsCryptoError;
    pub use dimpl::CryptoOperation as DtlsCryptoOperation;
    pub use dimpl::DtlsCertificate as DtlsCert;
    pub use dimpl::KeyingMaterial;
    pub use dimpl::ProtocolVersion;
    pub use dimpl::SrtpProfile;
    // Note: dimpl::Error is renamed to DtlsImplError to avoid conflict with str0m's DtlsError
    pub use dimpl::{Error as DtlsImplError, Output as DtlsOutput};
}
