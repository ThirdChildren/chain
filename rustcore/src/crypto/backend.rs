use crate::crypto::Hash;
use serde::{Deserialize, Serialize};

/// Trait for cryptographic keys with serialization capabilities
pub trait CryptoKey: Clone + std::fmt::Debug + Serialize + for<'de> Deserialize<'de> {
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

impl<Pub, Priv> Serialize for KeyPair<Pub, Priv>
where
    Pub: CryptoKey,
    Priv: CryptoKey,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("KeyPair", 2)?;
        state.serialize_field("public_key", &self.public_key)?;
        state.serialize_field("private_key", &self.private_key)?;
        state.end()
    }
}

impl<'de, Pub, Priv> Deserialize<'de> for KeyPair<Pub, Priv>
where
    Pub: CryptoKey,
    Priv: CryptoKey,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};
        use std::fmt;

        struct KeyPairVisitor<Pub, Priv>(std::marker::PhantomData<(Pub, Priv)>);

        impl<'de, Pub, Priv> Visitor<'de> for KeyPairVisitor<Pub, Priv>
        where
            Pub: CryptoKey,
            Priv: CryptoKey,
        {
            type Value = KeyPair<Pub, Priv>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct KeyPair")
            }

            fn visit_map<V>(self, mut map: V) -> Result<KeyPair<Pub, Priv>, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut public_key = None;
                let mut private_key = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        "public_key" => {
                            if public_key.is_some() {
                                return Err(de::Error::duplicate_field("public_key"));
                            }
                            public_key = Some(map.next_value()?);
                        }
                        "private_key" => {
                            if private_key.is_some() {
                                return Err(de::Error::duplicate_field("private_key"));
                            }
                            private_key = Some(map.next_value()?);
                        }
                        _ => {
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }
                let public_key = public_key.ok_or_else(|| de::Error::missing_field("public_key"))?;
                let private_key = private_key.ok_or_else(|| de::Error::missing_field("private_key"))?;
                Ok(KeyPair::new(public_key, private_key))
            }
        }

        const FIELDS: &'static [&'static str] = &["public_key", "private_key"];
        deserializer.deserialize_struct("KeyPair", FIELDS, KeyPairVisitor(std::marker::PhantomData))
    }
}

/// Trait for cryptographic signatures
pub trait CryptoSignature: Clone + std::fmt::Debug + Serialize + for<'de> Deserialize<'de> {
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