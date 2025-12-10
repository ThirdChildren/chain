use super::backend::{CryptoBackend, CryptoKey, CryptoSignature, KeyPair};
use crate::crypto::hash::Hash;
use ecdsa::{
    Signature as ECDSASignature, SigningKey, VerifyingKey, signature::Signer, signature::Verifier,
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

impl Default for Secp256k1Signature {
    fn default() -> Self {
        // Create a dummy signature using minimal valid DER encoding
        // DER format: 0x30 [total-length] 0x02 [r-length] [r] 0x02 [s-length] [s]
        // This is only used for initialization and will be overwritten by sign_input()
        // Using r=1 and s=1 as the smallest valid values
        let dummy_der = vec![
            0x30, 0x06, // SEQUENCE, 6 bytes total
            0x02, 0x01, 0x01, // INTEGER r = 1
            0x02, 0x01, 0x01, // INTEGER s = 1
        ];
        Secp256k1Signature(
            ECDSASignature::from_der(&dummy_der).expect("Failed to create default signature"),
        )
    }
}

impl Default for Secp256k1PublicKey {
    fn default() -> Self {
        // Create a dummy public key with a valid uncompressed point
        // Using the generator point (which is a valid public key)
        let generator = VerifyingKey::from_sec1_bytes(&[
            0x04, // uncompressed point prefix
            0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
            0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B,
            0x16, 0xF8, 0x17, 0x98, 0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4,
            0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8, 0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19,
            0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8,
        ])
        .expect("Failed to create default public key");
        Secp256k1PublicKey(generator)
    }
}

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
