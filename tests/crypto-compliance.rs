/// Test algorithm implementations for the CryptoProvider
///
/// This contains tests run against the installed crypto provider to verify
/// hash, cipher and signature implementations against known test vectors.
use str0m::crypto::CryptoProvider;

mod common;
use common::init_crypto_default;

fn get_provider() -> &'static CryptoProvider {
    init_crypto_default();
    CryptoProvider::get_default().unwrap()
}

/// Convert an ASCII hex array into a byte array at compile time.
macro_rules! hex_as_bytes {
    ($input:expr) => {{
        const fn from_hex_char(c: u8) -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => panic!("Invalid hex character"),
            }
        }

        const INPUT: &[u8] = $input;
        const LEN: usize = INPUT.len();
        const OUTPUT_LEN: usize = LEN / 2;

        const fn convert() -> [u8; OUTPUT_LEN] {
            assert!(LEN % 2 == 0, "Hex string length must be even");

            let mut out = [0u8; OUTPUT_LEN];
            let mut i = 0;
            while i < LEN {
                out[i / 2] = (from_hex_char(INPUT[i]) << 4) | from_hex_char(INPUT[i + 1]);
                i += 2;
            }
            out
        }

        convert()
    }};
}

mod sha256 {
    fn verify_test_vector(input: &[u8], expected: &[u8; 32]) {
        let sha256_provider = super::get_provider().sha256_provider;
        let hash = sha256_provider.sha256(input);
        assert_eq!(hash, *expected);
    }

    #[test]
    fn test_hello_world() {
        verify_test_vector(
            b"hello world",
            &hex_as_bytes!(b"b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"),
        );
    }

    #[test]
    fn test_empty() {
        // SHA-256 of "" - NIST test vector
        verify_test_vector(
            b"",
            &hex_as_bytes!(b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        );
    }

    #[test]
    fn test_abc() {
        // SHA-256 of "abc" - NIST test vector
        verify_test_vector(
            b"abc",
            &hex_as_bytes!(b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        );
    }
}

mod sha1_hmac {
    fn verify_test_vector(key: &[u8], payloads: &[&[u8]], expected: &[u8; 20]) {
        let sha1_hmac_provider = super::get_provider().sha1_hmac_provider;
        let hmac = sha1_hmac_provider.sha1_hmac(key, payloads);
        assert_eq!(hmac, *expected);
    }

    #[test]
    fn test_rfc2202_test_case_1() {
        verify_test_vector(
            &[0x0b; 20],
            &[b"Hi There"],
            &hex_as_bytes!(b"b617318655057264e28bc0b6fb378c8ef146be00"),
        );
    }

    #[test]
    fn test_rfc2202_test_case_2() {
        verify_test_vector(
            b"Jefe",
            &[b"what do ya want for nothing?"],
            &hex_as_bytes!(b"effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"),
        );
    }

    #[test]
    fn test_rfc2202_test_case_3() {
        verify_test_vector(
            &[0xaa; 20],
            &[&[0xddu8; 50]],
            &hex_as_bytes!(b"125d7342b9ac11cd91a39af48aa17b4f63f175d3"),
        );
    }

    #[test]
    fn test_rfc2202_test_case_4() {
        verify_test_vector(
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25,
            ],
            &[&[0xcdu8; 50]],
            &hex_as_bytes!(b"4c9007f4026250c6bc8414f9bf50c86c2d7235da"),
        );
    }

    #[test]
    fn test_rfc2202_test_case_5() {
        verify_test_vector(
            &[0x0c; 20],
            &[b"Test With Truncation"],
            &hex_as_bytes!(b"4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"),
        );
    }

    #[test]
    fn test_rfc2202_test_case_6() {
        verify_test_vector(
            &[0xaa; 80],
            &[b"Test Using Larger Than Block-Size Key - Hash Key First"],
            &hex_as_bytes!(b"aa4ae5e15272d00e95705637ce8a3b55ed402112"),
        );
    }

    #[test]
    fn test_rfc2202_test_case_7() {
        verify_test_vector(
            &[0xaa; 80],
            &[
                b"Test Using Larger Than Block-Size Key and Larger ",
                b"Than One Block-Size Data",
            ],
            &hex_as_bytes!(b"e8e99d0f45237d786d6bbaa7965c7808bbff1a91"),
        );
    }
}
