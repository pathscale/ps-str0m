//! Pure-Rust self-signed certificate generation for the RustCrypto DTLS backend.

use std::str::FromStr;
use std::time::Duration;

use p256::ecdsa::{DerSignature, SigningKey};
use p256::elliptic_curve::rand_core::{OsRng, RngCore};
use p256::pkcs8::EncodePrivateKey;
use str0m_proto::crypto::dtls::DtlsCert;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::Encode;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;

const CERTIFICATE_LIFETIME: Duration = Duration::from_secs(365 * 24 * 60 * 60);

pub(super) fn generate_certificate() -> Option<DtlsCert> {
    let mut rng = OsRng;
    let signing_key = SigningKey::random(&mut rng);
    let mut serial = [0u8; 16];
    rng.fill_bytes(&mut serial);

    let subject = Name::from_str("CN=DTLS Peer,O=DTLS").ok()?;
    let public_key = SubjectPublicKeyInfoOwned::from_key(*signing_key.verifying_key()).ok()?;
    let builder = CertificateBuilder::new(
        Profile::Leaf {
            issuer: subject.clone(),
            enable_key_agreement: false,
            enable_key_encipherment: false,
        },
        SerialNumber::new(&serial).ok()?,
        Validity::from_now(CERTIFICATE_LIFETIME).ok()?,
        subject,
        public_key,
        &signing_key,
    )
    .ok()?;
    let certificate = builder.build::<DerSignature>().ok()?.to_der().ok()?;
    let private_key = signing_key.to_pkcs8_der().ok()?.as_bytes().to_vec();

    Some(DtlsCert {
        certificate,
        private_key,
    })
}
