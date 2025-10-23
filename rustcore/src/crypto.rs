pub mod hash;
pub mod signature;
pub mod backend;

#[cfg(feature = "secp256k1")]
pub mod secp256k1;

#[cfg(feature = "mldsa")]
pub mod mldsa;

pub mod default;

pub use hash::{Hash, Hasher};
pub use signature::{Signature, PrivateKey, PublicKey};
pub use backend::{CryptoBackend, CryptoKey, CryptoSignature, KeyPair};

#[cfg(feature = "secp256k1")]
pub use secp256k1::{Secp256k1Backend, Secp256k1PublicKey, Secp256k1PrivateKey, Secp256k1Signature};

#[cfg(feature = "mldsa")]
pub use mldsa::{MLDSABackend, MLDSAPublicKey, MLDSAPrivateKey, MLDSASignature};

pub use default::{DefaultBackend, DefaultPublicKey, DefaultPrivateKey, DefaultSignature, DefaultKeyPair};