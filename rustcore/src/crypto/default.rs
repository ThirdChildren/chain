// Default crypto backend selection based on features

// ML-DSA (CRYSTALS-Dilithium) - Post-Quantum Cryptography
#[cfg(all(feature = "mldsa", not(feature = "secp256k1")))]
pub use super::mldsa::{MLDSABackend as DefaultBackend, MLDSAPublicKey as DefaultPublicKey, MLDSAPrivateKey as DefaultPrivateKey, MLDSASignature as DefaultSignature};

#[cfg(all(feature = "mldsa", not(feature = "secp256k1")))]
pub type DefaultKeyPair = super::backend::KeyPair<DefaultPublicKey, DefaultPrivateKey>;

// SECP256K1 - Traditional ECDSA (default)
#[cfg(feature = "secp256k1")]
pub use super::secp256k1::{Secp256k1Backend as DefaultBackend, Secp256k1PublicKey as DefaultPublicKey, Secp256k1PrivateKey as DefaultPrivateKey, Secp256k1Signature as DefaultSignature};

#[cfg(feature = "secp256k1")]
pub type DefaultKeyPair = super::backend::KeyPair<DefaultPublicKey, DefaultPrivateKey>;

// Future crypto backends can be added here with conditional compilation
// #[cfg(feature = "ed25519")]
// pub use super::ed25519::{Ed25519Backend as DefaultBackend, ...};

// Error if multiple backends are enabled simultaneously
#[cfg(all(feature = "secp256k1", feature = "mldsa"))]
compile_error!("Cannot enable multiple crypto backends simultaneously. Choose either 'secp256k1' or 'mldsa'.");

// Fallback - require at least one backend
#[cfg(not(any(feature = "secp256k1", feature = "mldsa")))]
compile_error!("Almeno un backend crittografico deve essere abilitato. Abilita 'secp256k1', 'mldsa' o un altro backend.");

pub use super::backend::CryptoBackend;