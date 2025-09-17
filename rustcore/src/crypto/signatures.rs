use rand::rngs::OsRng;
use ed25519_dalek::{Signer, Verifier, Signature, SigningKey};

pub struct KeyPair {
    pub private_key: SigningKey,
    pub public_key: ed25519_dalek::VerifyingKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let mut csprng = OsRng{};
        let private_key = SigningKey::generate(&mut csprng);
        let public_key = private_key.verifying_key();
        KeyPair { private_key, public_key }
    }

    pub fn sign_message(&self, message: &[u8]) -> Signature {
        self.private_key.sign(message)
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.public_key.verify(message, signature).is_ok()
    }
}