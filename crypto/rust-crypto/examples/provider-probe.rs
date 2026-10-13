use p256::ecdsa::{DerSignature, SigningKey, VerifyingKey, signature::Verifier};
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey};
use ps_str0m_rust_crypto::default_provider;
use sha2::{Digest, Sha256};
use str0m_proto::crypto::CryptoProvider;
use str0m_proto::crypto::dtls::DtlsCert;
use x509_cert::Certificate;
use x509_cert::der::{Decode, Encode};

fn main() {
    let provider = default_provider();
    let certificate = provider
        .dtls_provider
        .generate_certificate()
        .expect("RustCrypto provider did not generate a certificate");

    verify_certificate_and_key(&certificate);
    verify_certificate_fingerprint(&provider, &certificate);
    verify_srtp_authentication(&provider);

    println!("provider-probe: certificate, fingerprint, and SRTP authentication checks passed");
}

fn verify_certificate_and_key(certificate: &DtlsCert) {
    let parsed = Certificate::from_der(&certificate.certificate)
        .expect("provider certificate is not valid DER X.509");
    let subject_public_key_info = parsed
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .expect("certificate SPKI did not encode");
    let certificate_key = VerifyingKey::from_public_key_der(&subject_public_key_info)
        .expect("certificate SPKI is not a P-256 public key");
    let private_key = SigningKey::from_pkcs8_der(&certificate.private_key)
        .expect("provider private key is not valid P-256 PKCS#8");

    assert_eq!(
        private_key.verifying_key(),
        &certificate_key,
        "certificate public key does not match the returned private key"
    );

    let tbs_certificate = parsed
        .tbs_certificate
        .to_der()
        .expect("certificate TBS did not encode");
    let signature = DerSignature::from_bytes(
        parsed
            .signature
            .as_bytes()
            .expect("certificate signature is not octet-aligned"),
    )
    .expect("certificate signature is not a DER ECDSA signature");

    certificate_key
        .verify(&tbs_certificate, &signature)
        .expect("certificate signature did not verify with its matching P-256 key");
}

fn verify_certificate_fingerprint(provider: &CryptoProvider, certificate: &DtlsCert) {
    let expected: [u8; 32] = Sha256::digest(&certificate.certificate).into();
    assert_eq!(
        provider.sha256_provider.sha256(&certificate.certificate),
        expected,
        "provider SHA-256 does not match the certificate DER fingerprint"
    );
}

fn verify_srtp_authentication(provider: &CryptoProvider) {
    let key = [0x11; 32];
    let iv = [0x22; 12];
    let aad = b"ps-str0m provider probe";
    let plaintext = b"authenticated SRTP payload";

    let mut protected = vec![0; plaintext.len() + 16];
    let mut encryptor = provider
        .srtp_provider
        .aead_chacha20_poly1305()
        .create_cipher(key, true);
    encryptor
        .encrypt(&iv, aad, plaintext, &mut protected)
        .expect("provider failed to encrypt an SRTP AEAD payload");

    let mut recovered = vec![0; plaintext.len()];
    let mut decryptor = provider
        .srtp_provider
        .aead_chacha20_poly1305()
        .create_cipher(key, false);
    let recovered_len = decryptor
        .decrypt(&iv, &[aad], &protected, &mut recovered)
        .expect("provider failed to authenticate and decrypt an SRTP AEAD payload");
    assert_eq!(recovered_len, plaintext.len());
    assert_eq!(&recovered[..recovered_len], plaintext);

    let mut tampered = protected;
    *tampered.last_mut().expect("encrypted payload has no tag") ^= 1;
    let mut sink = vec![0; plaintext.len()];
    let mut rejecting_decryptor = provider
        .srtp_provider
        .aead_chacha20_poly1305()
        .create_cipher(key, false);
    assert!(
        rejecting_decryptor
            .decrypt(&iv, &[aad], &tampered, &mut sink)
            .is_err(),
        "provider accepted an SRTP payload with a tampered authentication tag"
    );
}
