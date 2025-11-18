use crate::crypto::hash::Hash;

pub trait CryptoKey: Clone + std::fmt::Debug {
    fn to_bytes(&self) -> Vec<u8>;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>>
    where
        Self: Sized;

    fn secret_key_bytes(&self) -> &[u8] {
        panic!("secret_key_bytes() not implemented for this key type");
    }

    fn embedded_public_key_bytes(&self) -> &[u8] {
        panic!("embedded_public_key_bytes() not implemented for this key type");
    }
}

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

pub trait CryptoSignature: Clone + std::fmt::Debug {
    fn to_bytes(&self) -> Vec<u8>;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>>
    where
        Self: Sized;
}

pub trait CryptoBackend {
    type PublicKey: CryptoKey;
    type PrivateKey: CryptoKey;
    type Signature: CryptoSignature;

    fn generate_keypair() -> KeyPair<Self::PublicKey, Self::PrivateKey>;

    fn public_key_from_private(private_key: &Self::PrivateKey) -> Self::PublicKey;

    fn sign(data: &Hash, private_key: &Self::PrivateKey) -> Self::Signature;

    fn verify(signature: &Self::Signature, data: &Hash, public_key: &Self::PublicKey) -> bool;
}

