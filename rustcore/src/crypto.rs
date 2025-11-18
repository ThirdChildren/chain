pub mod hash;
pub mod signature;

// Re-export hash types
pub use hash::{CryptoHash, CryptoHasher, Hash, HashBackend, Hashable, Hasher};
pub use hash::{DefaultHash, DefaultHashBackend, DefaultHasher};

#[cfg(feature = "blake3")]
pub use hash::{Blake3Backend, Blake3Hash, Blake3Hasher};

#[cfg(feature = "sha256")]
pub use hash::{Sha256Backend, Sha256CryptoHasher, Sha256Hash};

// Re-export signature types
pub use signature::{
    CryptoBackend, CryptoKey, CryptoSignature, KeyPair, PrivateKey, PublicKey, Signature,
};
pub use signature::{
    DefaultBackend, DefaultKeyPair, DefaultPrivateKey, DefaultPublicKey, DefaultSignature,
};

#[cfg(feature = "secp256k1")]
pub use signature::{
    Secp256k1Backend, Secp256k1PrivateKey, Secp256k1PublicKey, Secp256k1Signature,
};

#[cfg(feature = "mldsa")]
pub use signature::{MLDSABackend, MLDSAPrivateKey, MLDSAPublicKey, MLDSASignature};
