// Default hash backend selection based on features

// Blake3 (default)
#[cfg(feature = "blake3")]
pub use super::blake3::{
    Blake3Backend as DefaultHashBackend, Blake3Hash as DefaultHash, Blake3Hasher as DefaultHasher,
};

// SHA-256 (future implementation)
// #[cfg(all(feature = "sha256", not(feature = "blake3")))]
// pub use super::sha256::{Sha256Backend as DefaultHashBackend, Sha256Hash as DefaultHash, Sha256Hasher as DefaultHasher};

// SHA-3 (future implementation)
// #[cfg(all(feature = "sha3", not(any(feature = "blake3", feature = "sha256"))))]
// pub use super::sha3::{Sha3Backend as DefaultHashBackend, Sha3Hash as DefaultHash, Sha3Hasher as DefaultHasher};

// Error if no hash backend is enabled
#[cfg(not(feature = "blake3"))]
compile_error!(
    "At least one hash backend must be enabled. Enable 'blake3' or another hash backend."
);

pub use super::backend::HashBackend;
