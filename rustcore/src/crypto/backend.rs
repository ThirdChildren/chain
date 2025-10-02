use crate::crypto::Hash;

/// Trait for cryptographic keys with basic byte conversion
pub trait CryptoKey: Clone + std::fmt::Debug {
    /// Convert the key to bytes
    fn to_bytes(&self) -> Vec<u8>;
    
    /// Create a key from bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>>
    where
        Self: Sized;
}

/// A pair of cryptographic keys (public and private)
#[derive(Clone, Debug)]
pub struct KeyPair<Pub, Priv> 
where
    Pub: CryptoKey,
    Priv: CryptoKey,
{
    pub public_key: Pub,
    pub private_key: Priv,
}

impl<Pub, Priv> KeyPair<Pub, Priv>
where
    Pub: CryptoKey,
    Priv: CryptoKey,
{
    pub fn new(public_key: Pub, private_key: Priv) -> Self {
        Self {
            public_key,
            private_key,
        }
    }
}

/// Trait for cryptographic signatures
pub trait CryptoSignature: Clone + std::fmt::Debug {
    /// Convert the signature to bytes
    fn to_bytes(&self) -> Vec<u8>;
    
    /// Create a signature from bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>>
    where
        Self: Sized;
}

/// Main trait for cryptographic backends
pub trait CryptoBackend {
    type PublicKey: CryptoKey;
    type PrivateKey: CryptoKey;
    type Signature: CryptoSignature;
    
    /// Generate a new key pair
    fn generate_keypair() -> KeyPair<Self::PublicKey, Self::PrivateKey>;
    
    /// Extract public key from private key
    fn public_key_from_private(private_key: &Self::PrivateKey) -> Self::PublicKey;
    
    /// Sign data with a private key
    fn sign(data: &Hash, private_key: &Self::PrivateKey) -> Self::Signature;
    
    /// Verify a signature with a public key
    fn verify(signature: &Self::Signature, data: &Hash, public_key: &Self::PublicKey) -> bool;
}