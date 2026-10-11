//! SRTP cipher implementations using RustCrypto: ChaCha20-Poly1305 only, no AES.

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce, Tag};
use hkdf::Hkdf;
use sha2::Sha256;

use str0m_proto::crypto::CryptoError;
use str0m_proto::crypto::{AeadChacha20Poly1305, AeadChacha20Poly1305Cipher};
use str0m_proto::crypto::{SrtpProvider, SupportedAeadChacha20Poly1305};

// ============================================================================
// AEAD-ChaCha20-Poly1305 Cipher
// ============================================================================

struct RustCryptoAeadChacha20Poly1305Cipher {
    cipher: ChaCha20Poly1305,
}

impl std::fmt::Debug for RustCryptoAeadChacha20Poly1305Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustCryptoAeadChacha20Poly1305Cipher").finish()
    }
}

impl AeadChacha20Poly1305Cipher for RustCryptoAeadChacha20Poly1305Cipher {
    fn encrypt(
        &mut self,
        iv: &[u8; AeadChacha20Poly1305::IV_LEN],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        assert!(
            aad.len() >= 12,
            "Associated data length MUST be at least 12 octets"
        );
        let tag_len = AeadChacha20Poly1305::TAG_LEN;
        assert!(output.len() >= input.len() + tag_len);

        // In place in the caller's buffer: ciphertext, then the detached tag.
        let (body, rest) = output.split_at_mut(input.len());
        body.copy_from_slice(input);
        let tag = self
            .cipher
            .encrypt_in_place_detached(Nonce::from_slice(iv), aad, body)
            .map_err(|e| CryptoError::Other(format!("ChaCha20-Poly1305 encrypt failed: {:?}", e)))?;
        rest[..tag_len].copy_from_slice(&tag);
        Ok(())
    }

    fn decrypt(
        &mut self,
        iv: &[u8; AeadChacha20Poly1305::IV_LEN],
        aads: &[&[u8]],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        // Caller contract: `SrtpContext::unprotect_rtp` and `unprotect_rtcp` guarantee
        // the input holds at least the auth tag. A shorter buffer is a bug in str0m,
        // not bad input, so fail fast rather than hiding it in an error.
        let tag_len = AeadChacha20Poly1305::TAG_LEN;
        assert!(input.len() >= tag_len);

        let (ciphertext, tag) = input.split_at(input.len() - tag_len);
        let body = &mut output[..ciphertext.len()];
        body.copy_from_slice(ciphertext);

        // Poly1305 authenticates one contiguous AAD; only unencrypted SRTCP passes two pieces.
        let aad_vec: Vec<u8>;
        let aad = if aads.len() == 1 {
            aads[0]
        } else {
            aad_vec = aads.concat();
            &aad_vec
        };

        self.cipher
            .decrypt_in_place_detached(Nonce::from_slice(iv), aad, body, Tag::from_slice(tag))
            .map_err(|e| CryptoError::Other(format!("ChaCha20-Poly1305 decrypt failed: {:?}", e)))?;
        Ok(ciphertext.len())
    }
}

// ============================================================================
// SRTP Profile Support Implementation
// ============================================================================

struct RustCryptoSupportedAeadChacha20Poly1305;

impl std::fmt::Debug for RustCryptoSupportedAeadChacha20Poly1305 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustCryptoSupportedAeadChacha20Poly1305")
            .finish()
    }
}

impl SupportedAeadChacha20Poly1305 for RustCryptoSupportedAeadChacha20Poly1305 {
    fn create_cipher(
        &self,
        key: [u8; 32],
        _encrypt: bool,
    ) -> Box<dyn AeadChacha20Poly1305Cipher> {
        Box::new(RustCryptoAeadChacha20Poly1305Cipher {
            cipher: ChaCha20Poly1305::new(&key.into()),
        })
    }
}

// ============================================================================
// SRTP Provider Implementation
// ============================================================================

pub(super) struct RustCryptoSrtpProvider;

impl std::fmt::Debug for RustCryptoSrtpProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustCryptoSrtpProvider").finish()
    }
}

impl SrtpProvider for RustCryptoSrtpProvider {
    fn aead_chacha20_poly1305(&self) -> &'static dyn SupportedAeadChacha20Poly1305 {
        &RustCryptoSupportedAeadChacha20Poly1305
    }

    fn hkdf_sha256(&self, salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) {
        Hkdf::<Sha256>::new(Some(salt), ikm)
            .expand(info, out)
            // A session key or salt is far below HKDF-SHA256's 8160-byte output limit.
            .expect("HKDF-SHA256 output length");
    }
}
