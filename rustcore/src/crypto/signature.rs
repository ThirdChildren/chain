use ecdsa::{
    Signature as ECDSASignature,
};
use super::hash::Hash;
use super::backend::CryptoBackend;
use super::secp256k1::{Secp256k1Backend, Secp256k1PublicKey, Secp256k1PrivateKey, Secp256k1Signature};
use super::serialization::{CborFormat, SaveableKey};
use k256::Secp256k1;
use spki::EncodePublicKey;
use std::io::{Error as IoError, ErrorKind as IoErrorKind, Read, Result as IoResult, Write};
use crate::util::Saveable;

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

// Implement Saveable for backward compatibility using the new serialization system
impl Saveable for PrivateKey {
    fn load<I: Read>(reader: I) -> IoResult<Self> {
        let saveable_key: SaveableKey<PrivateKey, CborFormat> = SaveableKey::load(reader)?;
        Ok(saveable_key.into_key())
    }
    
    fn save<O: Write>(&self, writer: O) -> IoResult<()> {
        let saveable_key = SaveableKey::<PrivateKey, CborFormat>::new(self.clone());
        saveable_key.save(writer)
    }
}

// Custom PEM implementation for PublicKey to maintain backward compatibility
impl Saveable for PublicKey {
    fn load<I: Read>(mut reader: I) -> IoResult<Self> {
        // read PEM-encoded public key into string
        let mut buf = String::new();
        reader.read_to_string(&mut buf)?;

        // decode the public key from PEM
        let public_key = buf
            .parse()
            .map_err(|_| IoError::new(IoErrorKind::InvalidData, "Failed to parse PublicKey"))?;
        Ok(Secp256k1PublicKey(public_key))
    }
    
    fn save<O: Write>(&self, mut writer: O) -> IoResult<()> {
        let s = self
            .0
            .to_public_key_pem(Default::default())
            .map_err(|_| IoError::new(IoErrorKind::InvalidData, "Failed to serialize PublicKey"))?;
        writer.write_all(s.as_bytes())?;
        Ok(())
    }
}