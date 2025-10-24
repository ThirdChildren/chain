use super::hash::Hash;
use super::default::{DefaultBackend, DefaultPublicKey, DefaultPrivateKey, DefaultSignature, DefaultKeyPair};
use super::backend::CryptoBackend;

pub type PublicKey = DefaultPublicKey;
pub type PrivateKey = DefaultPrivateKey;
pub type Signature = DefaultSignature;
pub type KeyPair = DefaultKeyPair;

impl Signature {
    /// create a signature using the default backend
    pub fn sign_output(output_hash: &Hash, private_key: &PrivateKey) -> Self {
        <DefaultBackend as CryptoBackend>::sign(output_hash, private_key)
    }

    /// verify a signature using the default backend
    pub fn verify(&self, output_hash: &Hash, public_key: &PublicKey) -> bool {
        <DefaultBackend as CryptoBackend>::verify(self, output_hash, public_key)
    }
}

impl PrivateKey {
    /// Generate a new keypair using the default backend
    /// 
    /// Note: This method generates a full keypair but only returns the private key.
    /// For ML-DSA, you should use KeyPair::generate() instead to get both keys,
    /// as the public key cannot be efficiently derived from the private key alone.
    pub fn new_key() -> Self {
        let keypair = <DefaultBackend as CryptoBackend>::generate_keypair();
        keypair.private_key
    }
    
    /// Extract the public key from the private key using the default backend
    /// 
    /// Warning: For ML-DSA, this operation is not supported and will panic.
    /// Use KeyPair::generate() instead to get both keys at generation time.
    pub fn public_key(&self) -> PublicKey {
        <DefaultBackend as CryptoBackend>::public_key_from_private(self)
    }
}

impl KeyPair {
    /// Generate a new keypair using the default backend
    /// 
    /// This is the recommended way to generate keys, especially for ML-DSA,
    /// as it returns both the public and private keys.
    pub fn generate() -> Self {
        <DefaultBackend as CryptoBackend>::generate_keypair()
    }
}

impl PublicKey {
    /// Check if two public keys are equal
    pub fn equals(&self, other: &Self) -> bool {
        self == other
    }
}