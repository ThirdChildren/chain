use super::hash::Hash;
use super::default::{DefaultBackend, DefaultPublicKey, DefaultPrivateKey, DefaultSignature};
use super::backend::CryptoBackend;

// Type aliases semplici che usano sempre il default configurabile
pub type PublicKey = DefaultPublicKey;
pub type PrivateKey = DefaultPrivateKey;
pub type Signature = DefaultSignature;

impl Signature {
    /// Crea una nuova firma usando il backend default
    pub fn sign_output(output_hash: &Hash, private_key: &PrivateKey) -> Self {
        <DefaultBackend as CryptoBackend>::sign(output_hash, private_key)
    }
    
    /// Verifica una firma usando il backend default
    pub fn verify(&self, output_hash: &Hash, public_key: &PublicKey) -> bool {
        <DefaultBackend as CryptoBackend>::verify(self, output_hash, public_key)
    }
}

impl PrivateKey {
    /// Genera una nuova chiave privata usando il backend default
    pub fn new_key() -> Self {
        let keypair = <DefaultBackend as CryptoBackend>::generate_keypair();
        keypair.private_key
    }
    
    /// Estrae la chiave pubblica dalla privata usando il backend default
    pub fn public_key(&self) -> PublicKey {
        <DefaultBackend as CryptoBackend>::public_key_from_private(self)
    }
}

impl PublicKey {
    /// Verifica se due chiavi pubbliche sono uguali
    pub fn equals(&self, other: &Self) -> bool {
        self == other
    }
}