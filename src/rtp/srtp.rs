use std::fmt;
use std::panic::{RefUnwindSafe, UnwindSafe};

use zeroize::{Zeroize, Zeroizing};

use crate::crypto::dtls::{KeyingMaterial, SrtpProfile};
use crate::crypto::{AeadChacha20Poly1305, AeadChacha20Poly1305Cipher};
use crate::crypto::{CryptoProvider, SrtpProvider};
use crate::io::DATAGRAM_MAX_PACKET_SIZE;
use crate::RtcError;

use super::header::RtpHeader;

// Labels from RFC 3711 Section 4.3, used here as the HKDF info suffix that separates the RTP and RTCP
// session keys and salts.
const LABEL_RTP_ENCRYPTION: u8 = 0;
const LABEL_RTP_SALT: u8 = 2;
const LABEL_RTCP_ENCRYPTION: u8 = 3;
const LABEL_RTCP_SALT: u8 = 5;

/// HKDF info prefix; the RFC 3711 label byte follows it.
const KDF_INFO: &[u8] = b"ps-str0m SRTP ChaCha20-Poly1305 KDF";

// header = 4 bytes
// ssrc   = 4 bytes
// ssrtcp_index = 4 bytes
// tag = <T> bytes
// TOTAL overhead for SRTCP = 12 + T bytes.
// However, each RTCP packet must be on a 4 byte boundary since length is
// given in number of 4 bytes - 1 (making 0 valid).

pub const SRTP_BLOCK_SIZE: usize = 16;
const SRTCP_INDEX_LEN: usize = 4;
const SRTCP_INDEX_LIMIT: u32 = 1 << 31;
const SRTCP_HEADER_LEN: usize = 8;
const MAX_TAG_LEN: usize = AeadChacha20Poly1305::TAG_LEN;
pub const SRTCP_OVERHEAD: usize = MAX_TAG_LEN + SRTCP_INDEX_LEN;
pub const SRTP_OVERHEAD: usize = MAX_TAG_LEN;

/// Initial capacity for the RTP decryption scratch buffer, so `unprotect_rtp` never has to grow it.
const RX_SCRATCH_CAPACITY: usize = DATAGRAM_MAX_PACKET_SIZE;

impl SrtpContext {
    /// Create an SRTP context for the relevant profile using the provided keying material.
    pub fn new(
        crypto: &CryptoProvider,
        profile: SrtpProfile,
        mat: &KeyingMaterial,
        left: bool,
    ) -> Self {
        match profile {
            SrtpProfile::CHACHA20_POLY1305 => {
                let key = SrtpKey::new(mat, left);
                let mut scratch = [[0; AeadChacha20Poly1305::KEY_LEN]; 2];
                let (rtp, rtcp) =
                    Derived::aead_chacha20_poly1305(crypto.srtp_provider, &key, &mut scratch);

                SrtpContext {
                    rtp,
                    rtcp,
                    srtcp_index: 0,
                    rtcp_replay: std::collections::BTreeMap::new(),
                    rx_scratch: Vec::with_capacity(RX_SCRATCH_CAPACITY),
                }
            }
            _ => panic!("Unexpected SRTP profile: {profile:?}"),
        }
    }
}

#[derive(Debug)]
pub struct SrtpContext {
    /// Encryption/decryption derived from srtp_key for RTP.
    rtp: Derived,
    /// Encryption/decryption derived from srtp_key for RTCP.
    rtcp: Derived,
    /// Counter for outgoing SRTCP packets.
    srtcp_index: u32,
    rtcp_replay: std::collections::BTreeMap<u32, (u32, u64)>,
    /// Reusable scratch buffer for RTP decryption output. Reused across calls
    /// to `unprotect_rtp` so we don't allocate a fresh `Vec` per packet.
    rx_scratch: Vec<u8>,
}

/// SrtpContext contains cipher contexts that can't observe broken invariants after a panic.
impl UnwindSafe for SrtpContext {}
impl RefUnwindSafe for SrtpContext {}

impl SrtpContext {
    pub fn protect_rtp(
        &mut self,
        buf: &[u8],
        header: &RtpHeader,
        srtp_index: u64, // same as ext_seq
    ) -> Vec<u8> {
        // SRTP layout (RFC 7714 Section 5): the header is authenticated (AAD), the payload
        // (including RTP padding) is encrypted, and the AEAD tag follows.
        let hlen = header.header_len;
        let input = &buf[hlen..];

        let Derived { salt, enc, .. } = &mut self.rtp;
        let roc = (srtp_index >> 16) as u32;
        let iv = AeadChacha20Poly1305::rtp_iv_ref(salt, *header.ssrc, roc, header.sequence_number);
        let aad = &buf[..hlen];

        // Input and output lengths for encryption:
        // https://www.rfc-editor.org/rfc/rfc7714#section-5.2.1
        let mut output = vec![0_u8; buf.len() + AeadChacha20Poly1305::TAG_LEN];
        enc.encrypt(&iv, aad, input, &mut output[hlen..])
            .expect("rtp encrypt");

        output[..hlen].copy_from_slice(aad);

        output
    }

    /// Decrypts an SRTP packet into the internal reusable scratch buffer and
    /// returns a slice of the plaintext bytes. The returned slice borrows from
    /// `self` until the next mutable use; the scratch buffer is reused across
    /// calls to avoid per-packet allocation.
    pub fn unprotect_rtp(
        &mut self,
        buf: &[u8],
        header: &RtpHeader,
        srtp_index: u64, // same as ext_seq
    ) -> Option<&[u8]> {
        if buf.len() < header.header_len + AeadChacha20Poly1305::TAG_LEN {
            return None;
        }

        let Derived { salt, dec, .. } = &mut self.rtp;
        let roc: u32 = (srtp_index >> 16) as u32;
        let iv = AeadChacha20Poly1305::rtp_iv_ref(salt, *header.ssrc, roc, header.sequence_number);

        let (aad, input) = buf.split_at(header.header_len);
        // Input and output lengths for decryption:
        // https://www.rfc-editor.org/rfc/rfc7714#section-5.2.2
        let out_len = input.len() - AeadChacha20Poly1305::TAG_LEN;
        self.rx_scratch.resize(out_len, 0);

        if let Err(e) = dec.decrypt(&iv, &[aad], input, &mut self.rx_scratch) {
            warn!(
                "Failed to decrypt SRTP {} ({}): {}",
                SrtpProfile::CHACHA20_POLY1305,
                error_details(header, srtp_index),
                e
            );
            return None;
        }

        Some(&self.rx_scratch[..out_len])
    }

    pub(crate) fn srtcp_index_exhausted(&self) -> bool {
        self.srtcp_index >= SRTCP_INDEX_LIMIT
    }

    pub fn protect_rtcp(&mut self, buf: &[u8]) -> Result<Vec<u8>, RtcError> {
        if self.srtcp_index_exhausted() {
            return Err(RtcError::SrtcpIndexExhausted);
        }

        let srtcp_index = self.srtcp_index;
        // Keep the exhausted value so this key and salt never reuse an index.
        self.srtcp_index += 1;

        // The encryption flag occupies the high bit above the 31-bit index.
        let e_and_si = 0x8000_0000 | srtcp_index;
        let ssrc = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

        if ssrc == 0 {
            warn!("SSRC 0 does not make a good SRTCP IV");
        }

        let Derived { salt, enc, .. } = &mut self.rtcp;
        let iv = AeadChacha20Poly1305::rtcp_iv_ref(salt, ssrc, srtcp_index);

        let mut aad = [0; AeadChacha20Poly1305::RTCP_AAD_LEN];
        aad[..8].copy_from_slice(&buf[..8]);
        aad[8..12].copy_from_slice(&e_and_si.to_be_bytes());

        let mut output = vec![0_u8; buf.len() + SRTCP_INDEX_LEN + AeadChacha20Poly1305::TAG_LEN];
        output[0..8].copy_from_slice(&buf[0..8]);
        let input = &buf[8..];

        let enc_start = 8;
        let enc_end = input.len() + 8 + AeadChacha20Poly1305::TAG_LEN;
        let encout = &mut output[enc_start..enc_end];

        enc.encrypt(&iv, &aad, input, encout).expect("rtcp encrypt");

        let to = &mut output[enc_end..];
        to[0..4].copy_from_slice(&e_and_si.to_be_bytes());

        Ok(output)
    }

    // SRTCP layout
    // ["header", ssrc, payload, ["header", ssrc, payload], ...], ssrtcp_index, tag]
    //
    // |----------------------------------------------------------------------|
    //                          authenticated
    //
    //                  |--------------------------------------|
    //                                 encrypted
    pub fn unprotect_rtcp(&mut self, buf: &[u8]) -> Option<Vec<u8>> {
        if buf.len() < SRTCP_HEADER_LEN + SRTCP_INDEX_LEN + AeadChacha20Poly1305::TAG_LEN {
            // Too short
            return None;
        }

        let idx_start = buf.len() - SRTCP_INDEX_LEN;

        // Assume no MKI
        let e_and_si = u32::from_be_bytes(
            buf[idx_start..buf.len()]
                .try_into()
                // This is ok because SRTCP_INDEX_LEN is 4 bytes and the buffer is at least
                // that long.
                .expect("SRTCP_INDEX_LEN to be 4"),
        );
        let is_encrypted = e_and_si & 0x8000_0000 > 0;

        // The Encrypted Portion of an SRTCP packet consists of the encryption
        // of the RTCP payload of the equivalent compound RTCP packet, from the
        // first RTCP packet, i.e., from the ninth (9) octet to the end of the
        // compound packet.
        let input = if is_encrypted {
            &buf[8..idx_start]
        } else {
            // No encryption, but we still pass the tag down to decrypt so it can verify it.
            &buf[idx_start - AeadChacha20Poly1305::TAG_LEN..idx_start]
        };

        // The SRTCP index is a 31-bit counter for the SRTCP packet.
        let srtcp_index = e_and_si & 0x7fff_ffff;
        let ssrc = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let replay = if let Some(&(highest, bits)) = self.rtcp_replay.get(&ssrc) {
            if srtcp_index > highest {
                let shift = srtcp_index - highest;
                (
                    srtcp_index,
                    if shift >= 64 { 1 } else { (bits << shift) | 1 },
                )
            } else {
                let shift = highest - srtcp_index;
                if shift >= 64 || bits & (1u64 << shift) != 0 {
                    return None;
                }
                (highest, bits | (1u64 << shift))
            }
        } else {
            if self.rtcp_replay.len() >= 64 {
                return None;
            }
            (srtcp_index, 1)
        };

        let Derived { salt, dec, .. } = &mut self.rtcp;
        let iv = AeadChacha20Poly1305::rtcp_iv_ref(salt, ssrc, srtcp_index);
        // Declared out here for lifetime purposes, only used in the first branch of the if.
        let mut encrypted_aad = [0; AeadChacha20Poly1305::RTCP_AAD_LEN];
        let mut aads: [&[u8]; 2] = [&[], &[]];

        if is_encrypted {
            encrypted_aad[0..8].copy_from_slice(&buf[0..8]);
            encrypted_aad[8..12].copy_from_slice(&e_and_si.to_be_bytes());

            aads[0] = encrypted_aad.as_slice();
        } else {
            // The whole packet is AAD
            aads[0] = &buf[0..idx_start - AeadChacha20Poly1305::TAG_LEN];
            aads[1] = &buf[idx_start..];
        };

        let mut output = vec![0_u8; buf.len() - AeadChacha20Poly1305::TAG_LEN - SRTCP_INDEX_LEN];
        output[0..8].copy_from_slice(&buf[0..8]);

        let count = match dec.decrypt(&iv, &aads, input, &mut output[8..]) {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    "Failed to decrypt SRTCP {}: {}",
                    SrtpProfile::CHACHA20_POLY1305,
                    e
                );
                return None;
            }
        };

        if is_encrypted {
            output.truncate(8 + count);
        } else {
            // decrypt didn't error, the data is authenticated.
            output.copy_from_slice(
                &buf[0..buf.len() - SRTCP_INDEX_LEN - AeadChacha20Poly1305::TAG_LEN],
            )
        }

        self.rtcp_replay.insert(ssrc, replay);
        Some(output)
    }
}

/// Master key and salt for one direction, from the DTLS-SRTP keying material.
struct SrtpKey<'a> {
    master: &'a [u8],
    salt: &'a [u8],
}

impl<'a> SrtpKey<'a> {
    fn new(mat: &'a KeyingMaterial, left: bool) -> Self {
        // Layout: [left key, right key, left salt, right salt].
        const ML: usize = AeadChacha20Poly1305::KEY_LEN;
        const SL: usize = AeadChacha20Poly1305::SALT_LEN;

        // Invariant
        assert!(
            mat.len() == ML * 2 + SL * 2,
            "The KeyingMaterial provided to SrtpKey::new must be ML * 2 + SL * 2 in length"
        );

        let (master_offset, salt_offset) = if left { (0, 2 * ML) } else { (ML, 2 * ML + SL) };
        Self {
            master: &mat[master_offset..master_offset + ML],
            salt: &mat[salt_offset..salt_offset + SL],
        }
    }

    /// One session key or salt: HKDF-SHA256 over the master key, salted with the master salt, with
    /// the RFC 3711 label in the info so every output is independent.
    fn derive(&self, crypto: &dyn SrtpProvider, label: u8, out: &mut [u8]) {
        let mut info = [0_u8; KDF_INFO.len() + 1];
        info[..KDF_INFO.len()].copy_from_slice(KDF_INFO);
        info[KDF_INFO.len()] = label;
        crypto.hkdf_sha256(self.salt, self.master, &info, out);
    }
}

/// Encryption/decryption derived from the SrtpKey.
struct Derived {
    salt: Zeroizing<[u8; AeadChacha20Poly1305::SALT_LEN]>,
    enc: Box<dyn AeadChacha20Poly1305Cipher>,
    dec: Box<dyn AeadChacha20Poly1305Cipher>,
}

impl Derived {
    fn aead_chacha20_poly1305(
        crypto: &dyn SrtpProvider,
        srtp_key: &SrtpKey<'_>,
        scratch: &mut [[u8; AeadChacha20Poly1305::KEY_LEN]; 2],
    ) -> (Self, Self) {
        // Guard both KDF output buffers before giving them to the provider.
        struct WipeKeys<'a>(&'a mut [[u8; AeadChacha20Poly1305::KEY_LEN]; 2]);
        impl Drop for WipeKeys<'_> {
            fn drop(&mut self) {
                for key in &mut *self.0 {
                    key.zeroize();
                }
            }
        }

        let keys = WipeKeys(scratch);
        let [rtp_key, rtcp_key] = &mut *keys.0;
        srtp_key.derive(crypto, LABEL_RTP_ENCRYPTION, rtp_key);
        let mut rtp_salt = Zeroizing::new([0; AeadChacha20Poly1305::SALT_LEN]);
        srtp_key.derive(crypto, LABEL_RTP_SALT, &mut rtp_salt[..]);

        srtp_key.derive(crypto, LABEL_RTCP_ENCRYPTION, rtcp_key);
        let mut rtcp_salt = Zeroizing::new([0; AeadChacha20Poly1305::SALT_LEN]);
        srtp_key.derive(crypto, LABEL_RTCP_SALT, &mut rtcp_salt[..]);

        let cipher = crypto.aead_chacha20_poly1305();
        let rtp = Self {
            salt: rtp_salt,
            enc: cipher.create_cipher_from_key(rtp_key, true),
            dec: cipher.create_cipher_from_key(rtp_key, false),
        };
        let rtcp = Self {
            salt: rtcp_salt,
            enc: cipher.create_cipher_from_key(rtcp_key, true),
            dec: cipher.create_cipher_from_key(rtcp_key, false),
        };

        (rtp, rtcp)
    }
}

impl fmt::Debug for Derived {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Derived")
    }
}

fn error_details(header: &RtpHeader, srtp_index: u64) -> String {
    format!(
        "SSRC: {} seq_no: {} pt: {} mid: {:?} rid: {:?} rid_repair: {:?} srtp_index: {}",
        header.ssrc,
        header.sequence_number,
        header.payload_type,
        header.ext_vals.mid,
        header.ext_vals.rid,
        header.ext_vals.rid_repair,
        srtp_index
    )
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::Mutex;

    use super::{AeadChacha20Poly1305, Derived, SRTCP_INDEX_LIMIT, SrtpContext, SrtpKey};
    use crate::crypto::{
        SrtpProvider, SupportedAeadChacha20Poly1305,
        dtls::{KeyingMaterial, SrtpProfile},
        test_default_provider,
    };
    use crate::RtcError;

    #[test]
    fn derived_key_scratch_is_wiped_on_return_and_unwind() {
        #[derive(Debug)]
        struct PanicAtFactory<'a> {
            provider: &'a dyn SrtpProvider,
            derivations: Mutex<Vec<(u8, usize)>>,
        }

        impl SrtpProvider for PanicAtFactory<'_> {
            fn aead_chacha20_poly1305(&self) -> &'static dyn SupportedAeadChacha20Poly1305 {
                assert_eq!(
                    self.derivations.lock().unwrap().as_slice(),
                    &[(0, 32), (2, 12), (3, 32), (5, 12)]
                );
                panic!("simulated cipher factory panic");
            }

            fn hkdf_sha256(&self, salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) {
                self.provider.hkdf_sha256(salt, ikm, info, out);
                assert!(out.iter().any(|&byte| byte != 0));
                self.derivations.lock().unwrap().push((
                    *info.last().expect("SRTP KDF label"),
                    out.len(),
                ));
            }
        }

        let profile = SrtpProfile::CHACHA20_POLY1305;
        let material = KeyingMaterial::new(&vec![0x42; profile.keying_material_len()]);
        let master = SrtpKey::new(&material, true);
        let crypto = test_default_provider().srtp_provider;
        let mut scratch = [[0xa5; AeadChacha20Poly1305::KEY_LEN]; 2];

        let _derived = Derived::aead_chacha20_poly1305(crypto, &master, &mut scratch);
        assert!(scratch.iter().flatten().all(|&byte| byte == 0));

        let failing = PanicAtFactory {
            provider: crypto,
            derivations: Mutex::new(Vec::new()),
        };
        let result = catch_unwind(AssertUnwindSafe(|| {
            Derived::aead_chacha20_poly1305(&failing, &master, &mut scratch);
        }));
        let panic = result.expect_err("cipher factory should panic");
        assert_eq!(
            panic.downcast_ref::<&str>(),
            Some(&"simulated cipher factory panic")
        );
        assert!(scratch.iter().flatten().all(|&byte| byte == 0));
    }

    #[test]
    fn final_srtcp_index_is_sent_once_without_wrapping() {
        let profile = SrtpProfile::CHACHA20_POLY1305;
        let material_bytes = vec![0x42; profile.keying_material_len()];
        let material = KeyingMaterial::new(&material_bytes);
        let crypto = test_default_provider();
        let mut tx = SrtpContext::new(crypto, profile, &material, true);
        let mut rx = SrtpContext::new(crypto, profile, &material, true);
        let rtcp = [0x80, 201, 0, 1, 0x12, 0x34, 0x56, 0x78];

        tx.srtcp_index = SRTCP_INDEX_LIMIT - 1;
        let protected = tx.protect_rtcp(&rtcp).expect("final legal SRTCP index");

        let trailer = u32::from_be_bytes(
            protected[protected.len() - 4..]
                .try_into()
                .expect("four-byte SRTCP index"),
        );
        assert_eq!(trailer, u32::MAX);
        assert_eq!(rx.unprotect_rtcp(&protected).as_deref(), Some(rtcp.as_slice()));
        assert_eq!(tx.srtcp_index, SRTCP_INDEX_LIMIT);

        assert!(matches!(
            tx.protect_rtcp(&rtcp),
            Err(RtcError::SrtcpIndexExhausted)
        ));
        assert_eq!(tx.srtcp_index, SRTCP_INDEX_LIMIT);
    }
}
