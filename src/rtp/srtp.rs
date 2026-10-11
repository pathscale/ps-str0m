use std::fmt;
use std::panic::{RefUnwindSafe, UnwindSafe};

use crate::crypto::dtls::{KeyingMaterial, SrtpProfile};
use crate::crypto::{AeadChacha20Poly1305, AeadChacha20Poly1305Cipher};
use crate::crypto::{CryptoProvider, SrtpProvider};
use crate::io::DATAGRAM_MAX_PACKET_SIZE;

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
                let (rtp, rtcp) = Derived::aead_chacha20_poly1305(crypto.srtp_provider, &key);

                SrtpContext {
                    rtp,
                    rtcp,
                    srtcp_index: 0,
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
        let iv = AeadChacha20Poly1305::rtp_iv(*salt, *header.ssrc, roc, header.sequence_number);
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
        let iv = AeadChacha20Poly1305::rtp_iv(*salt, *header.ssrc, roc, header.sequence_number);

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

    pub fn protect_rtcp(&mut self, buf: &[u8]) -> Vec<u8> {
        let srtcp_index = self.srtcp_index;

        // https://tools.ietf.org/html/rfc3711#page-15
        // The SRTCP index MUST be set to zero before the first SRTCP
        // packet is sent, and MUST be incremented by one,
        // modulo 2^31, after each SRTCP packet is sent.
        self.srtcp_index = (self.srtcp_index + 1) % 2_u32.pow(31);

        // e is always encrypted, rest is 31 byte index.
        let e_and_si = 0x8000_0000 | srtcp_index;
        let ssrc = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

        if ssrc == 0 {
            warn!("SSRC 0 does not make a good SRTCP IV");
        }

        let Derived { salt, enc, .. } = &mut self.rtcp;
        let iv = AeadChacha20Poly1305::rtcp_iv(*salt, ssrc, srtcp_index);

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

        output
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

        let Derived { salt, dec, .. } = &mut self.rtcp;
        let iv = AeadChacha20Poly1305::rtcp_iv(*salt, ssrc, srtcp_index);
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

        Some(output)
    }
}

/// Master key and salt for one direction, from the DTLS-SRTP keying material.
#[derive(Debug)]
struct SrtpKey {
    master: [u8; AeadChacha20Poly1305::KEY_LEN],
    salt: [u8; AeadChacha20Poly1305::SALT_LEN],
}

impl SrtpKey {
    pub fn new(mat: &KeyingMaterial, left: bool) -> Self {
        // layout in SrtpKeyMaterial is [key_input, key_output, salt_input, salt_output]
        const ML: usize = AeadChacha20Poly1305::KEY_LEN;
        const SL: usize = AeadChacha20Poly1305::SALT_LEN;

        // Invariant
        assert!(
            mat.len() == ML * 2 + SL * 2,
            "The KeyingMaterial provided to SrtpKey::new must be ML * 2 + SL * 2 in length"
        );

        // offset 0, offset 1
        let (o0, o1) = if left { (0, 0) } else { (ML, SL) };

        let mut master = [0; ML];
        let mut salt = [0; SL];

        master.copy_from_slice(&mat[o0..(o0 + ML)]);
        salt.copy_from_slice(&mat[(ML + ML + o1)..(ML + ML + o1 + SL)]);

        SrtpKey { master, salt }
    }

    /// One session key or salt: HKDF-SHA256 over the master key, salted with the master salt, with
    /// the RFC 3711 label in the info so every output is independent. Replaces RFC 3711's AES-CM KDF.
    fn derive(&self, crypto: &dyn SrtpProvider, label: u8, out: &mut [u8]) {
        let mut info = [0_u8; KDF_INFO.len() + 1];
        info[..KDF_INFO.len()].copy_from_slice(KDF_INFO);
        info[KDF_INFO.len()] = label;
        crypto.hkdf_sha256(&self.salt, &self.master, &info, out);
    }
}

/// Encryption/decryption derived from the SrtpKey.
struct Derived {
    salt: [u8; AeadChacha20Poly1305::SALT_LEN],
    enc: Box<dyn AeadChacha20Poly1305Cipher>,
    dec: Box<dyn AeadChacha20Poly1305Cipher>,
}

impl Derived {
    fn aead_chacha20_poly1305(crypto: &dyn SrtpProvider, srtp_key: &SrtpKey) -> (Derived, Derived) {
        let mut rtp_key = [0; AeadChacha20Poly1305::KEY_LEN];
        srtp_key.derive(crypto, LABEL_RTP_ENCRYPTION, &mut rtp_key);
        let mut rtp_salt = [0; AeadChacha20Poly1305::SALT_LEN];
        srtp_key.derive(crypto, LABEL_RTP_SALT, &mut rtp_salt);

        let mut rtcp_key = [0; AeadChacha20Poly1305::KEY_LEN];
        srtp_key.derive(crypto, LABEL_RTCP_ENCRYPTION, &mut rtcp_key);
        let mut rtcp_salt = [0; AeadChacha20Poly1305::SALT_LEN];
        srtp_key.derive(crypto, LABEL_RTCP_SALT, &mut rtcp_salt);

        let cipher = crypto.aead_chacha20_poly1305();
        let rtp = Derived {
            salt: rtp_salt,
            enc: cipher.create_cipher(rtp_key, true),
            dec: cipher.create_cipher(rtp_key, false),
        };
        let rtcp = Derived {
            salt: rtcp_salt,
            enc: cipher.create_cipher(rtcp_key, true),
            dec: cipher.create_cipher(rtcp_key, false),
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
