use std::io;

use crate::IceError;

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub(crate) fn fill(bytes: &mut [u8]) -> Result<(), IceError> {
    use rand_core::{OsRng, RngCore};

    OsRng
        .try_fill_bytes(bytes)
        .map_err(|err| IceError::Entropy(io::Error::other(err)))
}

#[cfg(all(
    target_family = "wasm",
    target_os = "unknown",
    feature = "ice-entropy-js"
))]
pub(crate) fn fill(bytes: &mut [u8]) -> Result<(), IceError> {
    getrandom::getrandom(bytes).map_err(|err| IceError::Entropy(io::Error::other(err)))
}

#[cfg(all(
    target_family = "wasm",
    target_os = "unknown",
    not(feature = "ice-entropy-js")
))]
pub(crate) fn fill(_: &mut [u8]) -> Result<(), IceError> {
    Err(IceError::Entropy(io::Error::new(
        io::ErrorKind::Unsupported,
        "ICE randomness on this target requires the ice-entropy-js feature and a JavaScript host",
    )))
}
