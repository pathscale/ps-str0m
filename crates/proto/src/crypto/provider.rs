//! Cryptographic provider traits for pluggable crypto backends.
//!
//! This module defines the trait-based interface for cryptographic operations
//! in str0m, allowing users to provide custom crypto implementations for SRTP,
//! SHA1 HMAC (for STUN), and DTLS.
//!
//! Implementors of a crypto provider only need to depend on this module.

use std::fmt;
use std::fmt::Debug;
use std::panic::{RefUnwindSafe, UnwindSafe};
use std::sync::OnceLock;
use std::time::Instant;

use crate::crypto::dtls::*;
use crate::crypto::error::CryptoError;

// ============================================================================
// CryptoProvider
// ============================================================================

/// Cryptographic provider for SRTP, SHA1 HMAC, and DTLS operations.
///
/// This struct holds references to all cryptographic components needed
/// for WebRTC operations. Users can provide custom implementations of each component
/// to replace the default pure-Rust RustCrypto provider.
///
/// # Design
///
/// The provider uses static trait object references (`&'static dyn Trait`) which
/// provides zero runtime overhead for trait dispatch. This design is inspired by
/// dimpl's CryptoProvider and ensures efficient crypto operations.
#[derive(Debug, Clone)]
pub struct CryptoProvider {
    /// SRTP provider for creating cipher instances and key derivation.
    pub srtp_provider: &'static dyn SrtpProvider,
    /// SHA1 HMAC provider for STUN message integrity.
    pub sha1_hmac_provider: &'static dyn Sha1HmacProvider,
    /// SHA-256 hash provider.
    pub sha256_provider: &'static dyn Sha256Provider,
    /// DTLS provider for creating DTLS instances.
    pub dtls_provider: &'static dyn DtlsProvider,
}

/// CryptoProvider contains only static references to thread-safe traits,
/// so it's safe to use across panic boundaries.
impl UnwindSafe for CryptoProvider {}
impl RefUnwindSafe for CryptoProvider {}

/// Static storage for the default crypto provider.
static DEFAULT: OnceLock<CryptoProvider> = OnceLock::new();

impl CryptoProvider {
    /// Install this provider as the process-wide default.
    pub fn install_process_default(self) {
        let _ = DEFAULT.set(self);
    }

    /// Install a default crypto provider for the process.
    ///
    /// # Panics
    ///
    /// Panics if called more than once.
    pub fn install_default(provider: CryptoProvider) {
        DEFAULT
            .set(provider)
            .expect("CryptoProvider::install_default() called more than once");
    }

    /// Get the default crypto provider, if one has been installed.
    pub fn get_default() -> Option<&'static CryptoProvider> {
        DEFAULT.get()
    }
}

impl fmt::Display for CryptoProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CryptoProvider")
    }
}

// ============================================================================
// Marker Trait
// ============================================================================

pub use crate::{CryptoSafe, Sha1HmacProvider};

// ============================================================================
// Main Provider Traits
// ============================================================================

/// SRTP provider for creating cipher instances and key derivation.
///
/// The one profile is AEAD-ChaCha20-Poly1305, with session keys derived using HKDF-SHA256.
pub trait SrtpProvider: CryptoSafe {
    /// Factory for AEAD-ChaCha20-Poly1305 ciphers.
    fn aead_chacha20_poly1305(&self) -> &'static dyn SupportedAeadChacha20Poly1305;

    /// HKDF-SHA256 (RFC 5869) extract-and-expand of `ikm` with `salt` and `info`, filling `out`
    /// (at most 255 * 32 bytes). Used to derive the SRTP session keys and salts.
    fn hkdf_sha256(&self, salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]);
}

/// SHA-256 hash provider.
pub trait Sha256Provider: CryptoSafe {
    /// Compute SHA-256 hash of the input data.
    fn sha256(&self, data: &[u8]) -> [u8; 32];
}

/// Which DTLS version(s) to use for the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum DtlsVersion {
    /// Use only DTLS 1.2.
    #[default]
    Dtls12,
    /// Use only DTLS 1.3.
    Dtls13,
    /// Auto-detect: the first incoming ClientHello determines the version.
    Auto,
}

impl fmt::Display for DtlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DtlsVersion::Dtls12 => write!(f, "DTLS 1.2"),
            DtlsVersion::Dtls13 => write!(f, "DTLS 1.3"),
            DtlsVersion::Auto => write!(f, "DTLS Auto-detect"),
        }
    }
}

/// Factory for DTLS instances and certificates.
pub trait DtlsProvider: CryptoSafe {
    /// Generate a new self-signed DTLS certificate.
    ///
    /// Returns `None` if this provider does not support certificate generation.
    /// In that case, the user must supply a certificate via `RtcConfig::set_dtls_cert`.
    fn generate_certificate(&self) -> Option<DtlsCert>;

    /// Create a new DTLS instance with the given certificate.
    ///
    /// mtu: Backends that can size their record layer according to the provided MTU should do so;
    /// backends that cannot ignore it. `None` means use the backend's default.
    fn new_dtls(
        &self,
        cert: &DtlsCert,
        now: Instant,
        dtls_version: DtlsVersion,
        mtu: Option<usize>,
    ) -> Result<Box<dyn DtlsInstance>, CryptoError>;

    /// Whether the provider is used in a test context.
    fn is_test(&self) -> bool {
        cfg!(feature = "_internal_test_exports")
    }
}

// ============================================================================
// DTLS Instance Trait
// ============================================================================

/// DTLS instance operations (matches dimpl's Dtls API surface).
pub trait DtlsInstance: CryptoSafe {
    /// Set whether this instance is active (client) or passive (server).
    fn set_active(&mut self, active: bool);

    /// Handle an incoming DTLS packet.
    fn handle_packet(&mut self, packet: &[u8]) -> Result<(), DtlsImplError>;

    /// Poll for output from the DTLS instance.
    ///
    /// The buffer must be large enough to hold the largest possible DTLS record.
    fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> DtlsOutput<'a>;

    /// Handle a timeout event.
    fn handle_timeout(&mut self, now: Instant) -> Result<(), DtlsImplError>;

    /// Send application data over DTLS.
    fn send_application_data(&mut self, data: &[u8]) -> Result<(), DtlsImplError>;

    /// Return true if the instance is operating in the client role.
    fn is_active(&self) -> bool;

    /// Return the negotiated DTLS protocol version. May return `None` before handshake completion.
    fn protocol_version(&self) -> Option<ProtocolVersion>;

    /// Return true after close has started and while close output may still need polling.
    fn is_closing(&self) -> bool {
        false
    }

    /// Return true once close output has drained and the instance is closed.
    fn is_closed(&self) -> bool {
        false
    }

    /// Initiate graceful shutdown by sending a DTLS `close_notify` alert.
    fn close(&mut self) -> Result<(), DtlsImplError>;
}
// ============================================================================
// SRTP Cipher Factory Traits
// ============================================================================

/// Factory for AEAD-ChaCha20-Poly1305 cipher instances.
pub trait SupportedAeadChacha20Poly1305: CryptoSafe {
    /// Create a cipher instance with the given key.
    fn create_cipher(&self, key: [u8; 32], encrypt: bool) -> Box<dyn AeadChacha20Poly1305Cipher>;
}

// ============================================================================
// SRTP Cipher Instance Traits
// ============================================================================

/// AEAD-ChaCha20-Poly1305 cipher instance for SRTP encryption/decryption.
pub trait AeadChacha20Poly1305Cipher: CryptoSafe {
    /// Encrypt input with the given IV and AAD. `output` is `input.len() + TAG_LEN` bytes.
    fn encrypt(
        &mut self,
        iv: &[u8; 12],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError>;

    /// Decrypt input (ciphertext followed by the tag) with the given IV and AADs, which are
    /// authenticated in order. Returns the plaintext length written to `output`.
    fn decrypt(
        &mut self,
        iv: &[u8; 12],
        aads: &[&[u8]],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError>;
}

// ============================================================================
// SRTP Profile Definitions
// ============================================================================

/// AEAD-ChaCha20-Poly1305 SRTP profile.
///
/// The packet construction is RFC 7714's AEAD SRTP/SRTCP (AAD, IV and tag placement, E flag and
/// SRTCP index), with ChaCha20-Poly1305 (RFC 8439) as the AEAD. Session keys and salts come from
/// HKDF-SHA256 over the DTLS-exported master key and salt.
#[derive(Debug, Clone, Copy)]
pub struct AeadChacha20Poly1305;

impl AeadChacha20Poly1305 {
    /// Key length in bytes.
    pub const KEY_LEN: usize = 32;
    /// Salt length in bytes.
    pub const SALT_LEN: usize = 12;
    /// RTCP AAD length in bytes.
    pub const RTCP_AAD_LEN: usize = 12;
    /// Authentication tag length in bytes.
    pub const TAG_LEN: usize = 16;
    /// IV length in bytes.
    pub const IV_LEN: usize = 12;

    /// Compute RTP IV (RFC 7714 Section 8.1 layout).
    pub fn rtp_iv(salt: [u8; 12], ssrc: u32, roc: u32, seq: u16) -> [u8; 12] {
        let mut iv = [0; 12];

        iv[2..6].copy_from_slice(&ssrc.to_be_bytes());
        iv[6..10].copy_from_slice(&roc.to_be_bytes());
        iv[10..12].copy_from_slice(&seq.to_be_bytes());

        for i in 0..12 {
            iv[i] ^= salt[i];
        }

        iv
    }

    /// Compute RTCP IV (RFC 7714 Section 9.1 layout).
    pub fn rtcp_iv(salt: [u8; 12], ssrc: u32, srtcp_index: u32) -> [u8; 12] {
        let mut iv = [0; 12];

        iv[2..6].copy_from_slice(&ssrc.to_be_bytes());
        iv[8..12].copy_from_slice(&srtcp_index.to_be_bytes());

        for i in 0..12 {
            iv[i] ^= salt[i];
        }

        iv
    }
}
