use crate::crypto::Hash;
use super::backend::{CryptoBackend, CryptoKey, CryptoSignature, KeyPair};
use ecdsa::{
    Signature as ECDSASignature, SigningKey, VerifyingKey, 
    signature::Signer, signature::Verifier,
};
use k256::Secp256k1;
use k256::elliptic_curve::rand_core::OsRng;

/// ECDSA implementation using secp256k1 curve
pub struct Secp256k1Backend;

#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub struct Secp256k1PublicKey(pub VerifyingKey<Secp256k1>);

#[derive(Clone, Debug)]
pub struct Secp256k1PrivateKey(pub SigningKey<Secp256k1>);

#[derive(Clone, Debug)]
pub struct Secp256k1Signature(pub ECDSASignature<Secp256k1>);

impl CryptoKey for Secp256k1PublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_encoded_point(false).as_bytes().to_vec()
    }
    
    fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let verifying_key = VerifyingKey::from_sec1_bytes(bytes)?;
        Ok(Secp256k1PublicKey(verifying_key))
    }
}

impl CryptoKey for Secp256k1PrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
    
    fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let signing_key = SigningKey::from_slice(bytes)?;
        Ok(Secp256k1PrivateKey(signing_key))
    }
}

impl CryptoSignature for Secp256k1Signature {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_der().as_bytes().to_vec()
    }
    
    fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let signature = ECDSASignature::from_der(bytes)?;
        Ok(Secp256k1Signature(signature))
    }
}

impl CryptoBackend for Secp256k1Backend {
    type PublicKey = Secp256k1PublicKey;
    type PrivateKey = Secp256k1PrivateKey;
    type Signature = Secp256k1Signature;
    
    fn generate_keypair() -> KeyPair<Self::PublicKey, Self::PrivateKey> {
        let private_key = SigningKey::random(&mut OsRng);
        let public_key = private_key.verifying_key().clone();
        
        KeyPair::new(
            Secp256k1PublicKey(public_key),
            Secp256k1PrivateKey(private_key),
        )
    }
    
    fn public_key_from_private(private_key: &Self::PrivateKey) -> Self::PublicKey {
        Secp256k1PublicKey(private_key.0.verifying_key().clone())
    }
    
    fn sign(data: &Hash, private_key: &Self::PrivateKey) -> Self::Signature {
        let signature = private_key.0.sign(&data.as_bytes());
        Secp256k1Signature(signature)
    }
    
    fn verify(signature: &Self::Signature, data: &Hash, public_key: &Self::PublicKey) -> bool {
        public_key.0.verify(&data.as_bytes(), &signature.0).is_ok()
    }
}

