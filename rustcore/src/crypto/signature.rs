use ecdsa::{
    Signature as ECDSASignature,
};
use super::hash::Hash;
use super::backend::CryptoBackend;
use super::secp256k1::{Secp256k1Backend, Secp256k1PublicKey, Secp256k1PrivateKey, Secp256k1Signature};
use k256::Secp256k1;

// Type aliases for backward compatibility
pub type PublicKey = Secp256k1PublicKey;
pub type PrivateKey = Secp256k1PrivateKey;
pub type Signature = Secp256k1Signature;

impl Signature {
    pub fn new(signature: ECDSASignature<Secp256k1>) -> Self {
        Secp256k1Signature(signature)
    }
    
    pub fn sign_output(output_hash: &Hash, private_key: &PrivateKey) -> Self {
        <Secp256k1Backend as CryptoBackend>::sign(output_hash, private_key)
    }
    
    pub fn verify(&self, output_hash: &Hash, public_key: &PublicKey) -> bool {
        <Secp256k1Backend as CryptoBackend>::verify(self, output_hash, public_key)
    }
}

impl PrivateKey {
    pub fn new_key() -> Self {
        let keypair = <Secp256k1Backend as CryptoBackend>::generate_keypair();
        keypair.private_key
    }
    
    pub fn public_key(&self) -> PublicKey {
        <Secp256k1Backend as CryptoBackend>::public_key_from_private(self)
    }
}