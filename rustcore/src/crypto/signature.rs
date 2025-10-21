use super::hash::Hash;
use super::default::{DefaultBackend, DefaultPublicKey, DefaultPrivateKey, DefaultSignature};
use super::backend::CryptoBackend;

pub type PublicKey = DefaultPublicKey;
pub type PrivateKey = DefaultPrivateKey;
pub type Signature = DefaultSignature;

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
    /// generate a new private key using the default backend
    pub fn new_key() -> Self {
        let keypair = <DefaultBackend as CryptoBackend>::generate_keypair();
        keypair.private_key
    }
    
    /// Extract the public key from the private key using the default backend
    pub fn public_key(&self) -> PublicKey {
        <DefaultBackend as CryptoBackend>::public_key_from_private(self)
    }
}

impl PublicKey {
    /// Check if two public keys are equal
    pub fn equals(&self, other: &Self) -> bool {
        self == other
    }
}