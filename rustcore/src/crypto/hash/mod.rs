pub mod backend;
pub mod core;
pub mod default;

#[cfg(feature = "blake3")]
pub mod blake3;

#[cfg(feature = "sha256")]
pub mod sha256;

pub use backend::{CryptoHash, CryptoHasher, HashBackend};
pub use core::{Hash, Hashable, Hasher};
pub use default::{DefaultHash, DefaultHashBackend, DefaultHasher};

#[cfg(feature = "blake3")]
pub use blake3::{Blake3Backend, Blake3Hash, Blake3Hasher};

#[cfg(feature = "sha256")]
pub use sha256::{Sha256Backend, Sha256CryptoHasher, Sha256Hash};
