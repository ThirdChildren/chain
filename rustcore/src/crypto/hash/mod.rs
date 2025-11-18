pub mod backend;
pub mod blake3;
pub mod core;
pub mod default;

pub use backend::{CryptoHash, CryptoHasher, HashBackend};
pub use core::{Hash, Hashable, Hasher};
pub use default::{DefaultHash, DefaultHashBackend, DefaultHasher};

#[cfg(feature = "blake3")]
pub use blake3::{Blake3Backend, Blake3Hash, Blake3Hasher};

