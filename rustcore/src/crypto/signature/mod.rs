pub mod backend;
pub mod core;
pub mod default;

#[cfg(feature = "secp256k1")]
pub mod secp256k1;

#[cfg(feature = "mldsa")]
pub mod mldsa;

pub use backend::{CryptoBackend, CryptoKey, CryptoSignature, KeyPair as CryptoKeyPair};
pub use core::{KeyPair, PrivateKey, PublicKey, Signature};
pub use default::{
    DefaultBackend, DefaultKeyPair, DefaultPrivateKey, DefaultPublicKey, DefaultSignature,
};

#[cfg(feature = "secp256k1")]
pub use secp256k1::{
    Secp256k1Backend, Secp256k1PrivateKey, Secp256k1PublicKey, Secp256k1Signature,
};

#[cfg(feature = "mldsa")]
pub use mldsa::{MLDSABackend, MLDSAPrivateKey, MLDSAPublicKey, MLDSASignature};
