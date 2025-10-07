// Default crypto backend selection based on features

#[cfg(feature = "secp256k1")]
pub use super::secp256k1::{Secp256k1Backend as DefaultBackend, Secp256k1PublicKey as DefaultPublicKey, Secp256k1PrivateKey as DefaultPrivateKey, Secp256k1Signature as DefaultSignature};

#[cfg(feature = "secp256k1")]
pub type DefaultKeyPair = super::backend::KeyPair<DefaultPublicKey, DefaultPrivateKey>;

// Future crypto backends can be added here with conditional compilation
// #[cfg(feature = "ed25519")]
// pub use super::ed25519::{Ed25519Backend as DefaultBackend, ...};

// Fallback al secp256k1 se nessuna feature specifica è attiva
// (questo dovrebbe raramente accadere dato che secp256k1 è nel default)
#[cfg(not(any(feature = "secp256k1")))]
compile_error!("Almeno un backend crittografico deve essere abilitato. Abilita 'secp256k1' o un altro backend.");

pub use super::backend::CryptoBackend;