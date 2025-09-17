use rand::rngs::OsRng;
use ed25519_dalek::{Signature as ed25519_dalek_signature, SigningKey, VerifyingKey};
pub use ed25519_dalek::{Signer, Verifier};
use super::hash::Hash;

pub struct Signature(pub ed25519_dalek_signature);

impl Signature {
    pub fn new(signature: ed25519_dalek_signature) -> Self {
        Signature(signature)
    }

    pub fn sign_output(output_hash: &Hash, signing_key: &SigningKey) -> Self {
        let sig = signing_key.sign(output_hash.as_bytes());
        Signature::new(sig)
    }

    pub fn verify(&self, output_hash: &Hash, verifying_key: &VerifyingKey) -> bool {
        verifying_key.verify(output_hash.as_bytes(), &self.0).is_ok()
    }
}

pub struct PublicKey(pub VerifyingKey);
pub struct PrivateKey(pub SigningKey);

impl PrivateKey {
    pub fn new_key() -> Self {
        let mut csprng = OsRng{};
        let signing_key = SigningKey::generate(&mut csprng);
        PrivateKey(signing_key)
    }
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key().clone())
    }
}