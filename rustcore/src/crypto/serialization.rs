use super::backend::CryptoKey;
use serde::{Deserialize, Serialize};
use spki::EncodePublicKey;
use std::io::{Error as IoError, ErrorKind as IoErrorKind, Read, Result as IoResult, Write};
use crate::util::Saveable;

/// Trait for different serialization formats
pub trait SerializationFormat {
    fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
    fn deserialize<T: for<'de> Deserialize<'de>>(data: &[u8]) -> Result<T, Box<dyn std::error::Error>>;
}

/// CBOR serialization format
pub struct CborFormat;

impl SerializationFormat for CborFormat {
    fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut buffer = Vec::new();
        ciborium::ser::into_writer(value, &mut buffer)?;
        Ok(buffer)
    }
    
    fn deserialize<T: for<'de> Deserialize<'de>>(data: &[u8]) -> Result<T, Box<dyn std::error::Error>> {
        Ok(ciborium::de::from_reader(data)?)
    }
}

/// PEM serialization format (for public keys)
pub struct PemFormat;

impl PemFormat {
    pub fn serialize_public_key<K>(key: &K) -> Result<String, Box<dyn std::error::Error>>
    where
        K: spki::EncodePublicKey,
    {
        Ok(key.to_public_key_pem(Default::default())?)
    }
    
    pub fn deserialize_public_key(pem_data: &str) -> Result<k256::ecdsa::VerifyingKey, Box<dyn std::error::Error>> {
        Ok(pem_data.parse()?)
    }
}

/// Generic saveable wrapper for crypto keys and signatures
#[derive(Clone, Debug)]
pub struct SaveableKey<K, F> 
where
    K: CryptoKey,
    F: SerializationFormat,
{
    key: K,
    _format: std::marker::PhantomData<F>,
}

impl<K, F> SaveableKey<K, F>
where
    K: CryptoKey,
    F: SerializationFormat,
{
    pub fn new(key: K) -> Self {
        Self {
            key,
            _format: std::marker::PhantomData,
        }
    }
    
    pub fn key(&self) -> &K {
        &self.key
    }
    
    pub fn into_key(self) -> K {
        self.key
    }
}

impl<K, F> Serialize for SaveableKey<K, F>
where
    K: CryptoKey,
    F: SerializationFormat,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.key.serialize(serializer)
    }
}

impl<'de, K, F> Deserialize<'de> for SaveableKey<K, F>
where
    K: CryptoKey,
    F: SerializationFormat,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let key = K::deserialize(deserializer)?;
        Ok(Self::new(key))
    }
}

impl<K, F> Saveable for SaveableKey<K, F>
where
    K: CryptoKey,
    F: SerializationFormat,
{
    fn load<I: Read>(mut reader: I) -> IoResult<Self> {
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer)?;
        
        let key = F::deserialize(&buffer)
            .map_err(|e| IoError::new(IoErrorKind::InvalidData, e.to_string()))?;
        
        Ok(Self::new(key))
    }
    
    fn save<O: Write>(&self, mut writer: O) -> IoResult<()> {
        let data = F::serialize(&self.key)
            .map_err(|e| IoError::new(IoErrorKind::InvalidData, e.to_string()))?;
        
        writer.write_all(&data)?;
        Ok(())
    }
}

/// Specific implementation for PEM format public keys
pub struct SaveablePublicKeyPem<K> 
where
    K: CryptoKey + spki::EncodePublicKey,
{
    key: K,
}

impl<K> SaveablePublicKeyPem<K>
where
    K: CryptoKey + spki::EncodePublicKey,
{
    pub fn new(key: K) -> Self {
        Self { key }
    }
    
    pub fn key(&self) -> &K {
        &self.key
    }
    
    pub fn into_key(self) -> K {
        self.key
    }
}

impl<K> Saveable for SaveablePublicKeyPem<K>
where
    K: CryptoKey + spki::EncodePublicKey,
{
    fn load<I: Read>(mut reader: I) -> IoResult<Self> {
        let mut pem_string = String::new();
        reader.read_to_string(&mut pem_string)?;
        
        // This is a simplified version - in practice you'd need to implement
        // PEM parsing for your specific key type
        todo!("Implement PEM parsing for specific key type")
    }
    
    fn save<O: Write>(&self, mut writer: O) -> IoResult<()> {
        let pem_string = self.key.to_public_key_pem(Default::default())
            .map_err(|e| IoError::new(IoErrorKind::InvalidData, e.to_string()))?;
        
        writer.write_all(pem_string.as_bytes())?;
        Ok(())
    }
}